rule TTP_XOR_WriteProcessMemory_3f49 {
  strings:
    $key_3f49 = { 68 3b [2] 5a 19 [2] 5c 2c [2] 72 2c [2] 4d 30 }

  condition:
    any of them
}