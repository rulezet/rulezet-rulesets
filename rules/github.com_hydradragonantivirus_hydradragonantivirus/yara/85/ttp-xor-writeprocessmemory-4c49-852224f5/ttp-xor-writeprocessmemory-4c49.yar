rule TTP_XOR_WriteProcessMemory_4c49 {
  strings:
    $key_4c49 = { 1b 3b [2] 29 19 [2] 2f 2c [2] 01 2c [2] 3e 30 }

  condition:
    any of them
}