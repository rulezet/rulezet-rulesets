rule TTP_XOR_WriteProcessMemory_2c60 {
  strings:
    $key_2c60 = { 7b 12 [2] 49 30 [2] 4f 05 [2] 61 05 [2] 5e 19 }

  condition:
    any of them
}