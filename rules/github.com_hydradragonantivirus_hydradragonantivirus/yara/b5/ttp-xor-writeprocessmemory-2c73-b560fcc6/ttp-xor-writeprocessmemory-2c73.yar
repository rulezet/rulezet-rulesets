rule TTP_XOR_WriteProcessMemory_2c73 {
  strings:
    $key_2c73 = { 7b 01 [2] 49 23 [2] 4f 16 [2] 61 16 [2] 5e 0a }

  condition:
    any of them
}