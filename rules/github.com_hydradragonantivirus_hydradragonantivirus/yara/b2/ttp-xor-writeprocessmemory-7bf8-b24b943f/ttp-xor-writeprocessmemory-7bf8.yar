rule TTP_XOR_WriteProcessMemory_7bf8 {
  strings:
    $key_7bf8 = { 2c 8a [2] 1e a8 [2] 18 9d [2] 36 9d [2] 09 81 }

  condition:
    any of them
}