rule TTP_XOR_WriteProcessMemory_3b49 {
  strings:
    $key_3b49 = { 6c 3b [2] 5e 19 [2] 58 2c [2] 76 2c [2] 49 30 }

  condition:
    any of them
}