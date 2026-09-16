rule TTP_XOR_WriteProcessMemory_6c49 {
  strings:
    $key_6c49 = { 3b 3b [2] 09 19 [2] 0f 2c [2] 21 2c [2] 1e 30 }

  condition:
    any of them
}