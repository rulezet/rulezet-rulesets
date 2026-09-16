rule TTP_XOR_WriteProcessMemory_2c49 {
  strings:
    $key_2c49 = { 7b 3b [2] 49 19 [2] 4f 2c [2] 61 2c [2] 5e 30 }

  condition:
    any of them
}