rule TTP_XOR_WriteProcessMemory_3c49 {
  strings:
    $key_3c49 = { 6b 3b [2] 59 19 [2] 5f 2c [2] 71 2c [2] 4e 30 }

  condition:
    any of them
}