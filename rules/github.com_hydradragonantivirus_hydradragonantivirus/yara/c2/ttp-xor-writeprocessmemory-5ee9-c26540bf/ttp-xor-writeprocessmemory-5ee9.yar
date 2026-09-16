rule TTP_XOR_WriteProcessMemory_5ee9 {
  strings:
    $key_5ee9 = { 09 9b [2] 3b b9 [2] 3d 8c [2] 13 8c [2] 2c 90 }

  condition:
    any of them
}