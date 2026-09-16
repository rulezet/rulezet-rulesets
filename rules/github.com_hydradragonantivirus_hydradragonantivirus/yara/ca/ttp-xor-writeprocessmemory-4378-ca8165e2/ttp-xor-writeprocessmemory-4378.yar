rule TTP_XOR_WriteProcessMemory_4378 {
  strings:
    $key_4378 = { 14 0a [2] 26 28 [2] 20 1d [2] 0e 1d [2] 31 01 }

  condition:
    any of them
}