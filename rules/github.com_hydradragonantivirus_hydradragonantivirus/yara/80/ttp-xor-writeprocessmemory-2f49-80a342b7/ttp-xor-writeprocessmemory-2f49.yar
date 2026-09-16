rule TTP_XOR_WriteProcessMemory_2f49 {
  strings:
    $key_2f49 = { 78 3b [2] 4a 19 [2] 4c 2c [2] 62 2c [2] 5d 30 }

  condition:
    any of them
}