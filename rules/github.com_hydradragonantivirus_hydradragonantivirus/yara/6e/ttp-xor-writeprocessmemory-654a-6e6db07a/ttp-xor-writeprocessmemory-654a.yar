rule TTP_XOR_WriteProcessMemory_654a {
  strings:
    $key_654a = { 32 38 [2] 00 1a [2] 06 2f [2] 28 2f [2] 17 33 }

  condition:
    any of them
}