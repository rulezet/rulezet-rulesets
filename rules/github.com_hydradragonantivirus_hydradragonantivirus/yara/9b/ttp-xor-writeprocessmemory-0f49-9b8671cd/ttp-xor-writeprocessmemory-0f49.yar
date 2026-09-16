rule TTP_XOR_WriteProcessMemory_0f49 {
  strings:
    $key_0f49 = { 58 3b [2] 6a 19 [2] 6c 2c [2] 42 2c [2] 7d 30 }

  condition:
    any of them
}