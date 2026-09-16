rule TTP_XOR_WriteProcessMemory_6b49 {
  strings:
    $key_6b49 = { 3c 3b [2] 0e 19 [2] 08 2c [2] 26 2c [2] 19 30 }

  condition:
    any of them
}