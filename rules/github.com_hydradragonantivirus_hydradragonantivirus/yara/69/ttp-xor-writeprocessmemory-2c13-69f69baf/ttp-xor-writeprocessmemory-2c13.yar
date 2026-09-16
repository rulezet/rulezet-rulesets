rule TTP_XOR_WriteProcessMemory_2c13 {
  strings:
    $key_2c13 = { 7b 61 [2] 49 43 [2] 4f 76 [2] 61 76 [2] 5e 6a }

  condition:
    any of them
}