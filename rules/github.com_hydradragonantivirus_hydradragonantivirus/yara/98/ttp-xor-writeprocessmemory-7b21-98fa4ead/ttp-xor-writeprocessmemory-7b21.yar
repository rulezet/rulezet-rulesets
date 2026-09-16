rule TTP_XOR_WriteProcessMemory_7b21 {
  strings:
    $key_7b21 = { 2c 53 [2] 1e 71 [2] 18 44 [2] 36 44 [2] 09 58 }

  condition:
    any of them
}