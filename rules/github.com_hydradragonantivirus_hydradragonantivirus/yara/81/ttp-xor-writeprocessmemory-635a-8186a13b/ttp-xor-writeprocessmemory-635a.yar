rule TTP_XOR_WriteProcessMemory_635a {
  strings:
    $key_635a = { 34 28 [2] 06 0a [2] 00 3f [2] 2e 3f [2] 11 23 }

  condition:
    any of them
}