rule TTP_XOR_WriteProcessMemory_a53d {
  strings:
    $key_a53d = { f2 4f [2] c0 6d [2] c6 58 [2] e8 58 [2] d7 44 }

  condition:
    any of them
}