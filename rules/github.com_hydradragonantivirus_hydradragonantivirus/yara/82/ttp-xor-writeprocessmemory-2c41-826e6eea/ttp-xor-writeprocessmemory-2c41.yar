rule TTP_XOR_WriteProcessMemory_2c41 {
  strings:
    $key_2c41 = { 7b 33 [2] 49 11 [2] 4f 24 [2] 61 24 [2] 5e 38 }

  condition:
    any of them
}