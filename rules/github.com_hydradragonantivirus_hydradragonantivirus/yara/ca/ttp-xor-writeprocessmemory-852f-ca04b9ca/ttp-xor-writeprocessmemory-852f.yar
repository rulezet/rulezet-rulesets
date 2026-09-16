rule TTP_XOR_WriteProcessMemory_852f {
  strings:
    $key_852f = { d2 5d [2] e0 7f [2] e6 4a [2] c8 4a [2] f7 56 }

  condition:
    any of them
}