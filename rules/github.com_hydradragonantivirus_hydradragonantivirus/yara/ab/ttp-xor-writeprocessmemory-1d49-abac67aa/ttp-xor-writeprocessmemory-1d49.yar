rule TTP_XOR_WriteProcessMemory_1d49 {
  strings:
    $key_1d49 = { 4a 3b [2] 78 19 [2] 7e 2c [2] 50 2c [2] 6f 30 }

  condition:
    any of them
}