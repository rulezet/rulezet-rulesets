rule TTP_XOR_WriteProcessMemory_2c42 {
  strings:
    $key_2c42 = { 7b 30 [2] 49 12 [2] 4f 27 [2] 61 27 [2] 5e 3b }

  condition:
    any of them
}