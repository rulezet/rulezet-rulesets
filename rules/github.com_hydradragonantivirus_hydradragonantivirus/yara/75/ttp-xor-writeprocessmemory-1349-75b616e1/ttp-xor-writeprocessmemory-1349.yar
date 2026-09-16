rule TTP_XOR_WriteProcessMemory_1349 {
  strings:
    $key_1349 = { 44 3b [2] 76 19 [2] 70 2c [2] 5e 2c [2] 61 30 }

  condition:
    any of them
}