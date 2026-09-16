rule TTP_XOR_WriteProcessMemory_5ef9 {
  strings:
    $key_5ef9 = { 09 8b [2] 3b a9 [2] 3d 9c [2] 13 9c [2] 2c 80 }

  condition:
    any of them
}