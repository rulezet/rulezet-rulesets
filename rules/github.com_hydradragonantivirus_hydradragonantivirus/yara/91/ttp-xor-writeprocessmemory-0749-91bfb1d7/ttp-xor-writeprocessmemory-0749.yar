rule TTP_XOR_WriteProcessMemory_0749 {
  strings:
    $key_0749 = { 50 3b [2] 62 19 [2] 64 2c [2] 4a 2c [2] 75 30 }

  condition:
    any of them
}