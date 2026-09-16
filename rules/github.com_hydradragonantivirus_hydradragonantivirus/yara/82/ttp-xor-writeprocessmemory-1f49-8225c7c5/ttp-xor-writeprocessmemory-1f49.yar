rule TTP_XOR_WriteProcessMemory_1f49 {
  strings:
    $key_1f49 = { 48 3b [2] 7a 19 [2] 7c 2c [2] 52 2c [2] 6d 30 }

  condition:
    any of them
}