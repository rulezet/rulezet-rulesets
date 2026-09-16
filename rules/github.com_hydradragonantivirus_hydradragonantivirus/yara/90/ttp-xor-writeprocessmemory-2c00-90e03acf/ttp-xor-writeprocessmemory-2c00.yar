rule TTP_XOR_WriteProcessMemory_2c00 {
  strings:
    $key_2c00 = { 7b 72 [2] 49 50 [2] 4f 65 [2] 61 65 [2] 5e 79 }

  condition:
    any of them
}