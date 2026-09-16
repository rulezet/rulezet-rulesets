rule TTP_XOR_WriteProcessMemory_7b51 {
  strings:
    $key_7b51 = { 2c 23 [2] 1e 01 [2] 18 34 [2] 36 34 [2] 09 28 }

  condition:
    any of them
}