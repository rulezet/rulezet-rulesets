rule TTP_XOR_WriteProcessMemory_2c61 {
  strings:
    $key_2c61 = { 7b 13 [2] 49 31 [2] 4f 04 [2] 61 04 [2] 5e 18 }

  condition:
    any of them
}