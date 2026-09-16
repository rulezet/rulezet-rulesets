rule TTP_XOR_WriteProcessMemory_7b40 {
  strings:
    $key_7b40 = { 2c 32 [2] 1e 10 [2] 18 25 [2] 36 25 [2] 09 39 }

  condition:
    any of them
}