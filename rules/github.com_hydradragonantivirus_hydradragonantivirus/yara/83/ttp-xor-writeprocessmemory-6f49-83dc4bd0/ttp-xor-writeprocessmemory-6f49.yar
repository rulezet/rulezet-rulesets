rule TTP_XOR_WriteProcessMemory_6f49 {
  strings:
    $key_6f49 = { 38 3b [2] 0a 19 [2] 0c 2c [2] 22 2c [2] 1d 30 }

  condition:
    any of them
}