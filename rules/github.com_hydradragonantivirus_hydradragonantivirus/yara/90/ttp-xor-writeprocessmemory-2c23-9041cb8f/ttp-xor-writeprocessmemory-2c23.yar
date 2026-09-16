rule TTP_XOR_WriteProcessMemory_2c23 {
  strings:
    $key_2c23 = { 7b 51 [2] 49 73 [2] 4f 46 [2] 61 46 [2] 5e 5a }

  condition:
    any of them
}