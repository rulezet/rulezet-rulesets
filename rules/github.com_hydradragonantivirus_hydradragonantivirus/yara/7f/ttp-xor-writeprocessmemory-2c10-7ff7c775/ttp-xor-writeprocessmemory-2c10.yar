rule TTP_XOR_WriteProcessMemory_2c10 {
  strings:
    $key_2c10 = { 7b 62 [2] 49 40 [2] 4f 75 [2] 61 75 [2] 5e 69 }

  condition:
    any of them
}