rule TTP_XOR_WriteProcessMemory_852a {
  strings:
    $key_852a = { d2 58 [2] e0 7a [2] e6 4f [2] c8 4f [2] f7 53 }

  condition:
    any of them
}