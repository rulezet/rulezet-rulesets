rule TTP_XOR_WriteProcessMemory_6378 {
  strings:
    $key_6378 = { 34 0a [2] 06 28 [2] 00 1d [2] 2e 1d [2] 11 01 }

  condition:
    any of them
}