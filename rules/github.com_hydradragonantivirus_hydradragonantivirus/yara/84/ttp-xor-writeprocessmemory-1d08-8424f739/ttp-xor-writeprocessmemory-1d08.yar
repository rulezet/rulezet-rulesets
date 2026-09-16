rule TTP_XOR_WriteProcessMemory_1d08 {
  strings:
    $key_1d08 = { 4a 7a [2] 78 58 [2] 7e 6d [2] 50 6d [2] 6f 71 }

  condition:
    any of them
}