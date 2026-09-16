rule TTP_XOR_WriteProcessMemory_b42f {
  strings:
    $key_b42f = { e3 5d [2] d1 7f [2] d7 4a [2] f9 4a [2] c6 56 }

  condition:
    any of them
}