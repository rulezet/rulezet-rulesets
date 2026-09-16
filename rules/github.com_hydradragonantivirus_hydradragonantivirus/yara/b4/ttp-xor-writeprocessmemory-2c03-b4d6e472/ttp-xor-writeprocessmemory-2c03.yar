rule TTP_XOR_WriteProcessMemory_2c03 {
  strings:
    $key_2c03 = { 7b 71 [2] 49 53 [2] 4f 66 [2] 61 66 [2] 5e 7a }

  condition:
    any of them
}