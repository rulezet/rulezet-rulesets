rule TTP_XOR_WriteProcessMemory_4d08 {
  strings:
    $key_4d08 = { 1a 7a [2] 28 58 [2] 2e 6d [2] 00 6d [2] 3f 71 }

  condition:
    any of them
}