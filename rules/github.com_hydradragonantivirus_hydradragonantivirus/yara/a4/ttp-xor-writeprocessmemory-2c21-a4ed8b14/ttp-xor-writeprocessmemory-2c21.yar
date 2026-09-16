rule TTP_XOR_WriteProcessMemory_2c21 {
  strings:
    $key_2c21 = { 7b 53 [2] 49 71 [2] 4f 44 [2] 61 44 [2] 5e 58 }

  condition:
    any of them
}