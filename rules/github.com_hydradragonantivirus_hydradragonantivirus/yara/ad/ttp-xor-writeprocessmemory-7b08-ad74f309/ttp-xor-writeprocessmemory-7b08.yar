rule TTP_XOR_WriteProcessMemory_7b08 {
  strings:
    $key_7b08 = { 2c 7a [2] 1e 58 [2] 18 6d [2] 36 6d [2] 09 71 }

  condition:
    any of them
}