rule TTP_XOR_WriteProcessMemory_4ff9 {
  strings:
    $key_4ff9 = { 18 8b [2] 2a a9 [2] 2c 9c [2] 02 9c [2] 3d 80 }

  condition:
    any of them
}