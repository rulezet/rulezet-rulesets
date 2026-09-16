rule TTP_XOR_WriteProcessMemory_0349 {
  strings:
    $key_0349 = { 54 3b [2] 66 19 [2] 60 2c [2] 4e 2c [2] 71 30 }

  condition:
    any of them
}