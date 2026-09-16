rule TTP_XOR_WriteProcessMemory_1849 {
  strings:
    $key_1849 = { 4f 3b [2] 7d 19 [2] 7b 2c [2] 55 2c [2] 6a 30 }

  condition:
    any of them
}