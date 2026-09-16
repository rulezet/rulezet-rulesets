rule TTP_XOR_WriteProcessMemory_6d49 {
  strings:
    $key_6d49 = { 3a 3b [2] 08 19 [2] 0e 2c [2] 20 2c [2] 1f 30 }

  condition:
    any of them
}