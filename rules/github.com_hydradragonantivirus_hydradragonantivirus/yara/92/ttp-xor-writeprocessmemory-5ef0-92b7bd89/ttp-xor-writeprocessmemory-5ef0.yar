rule TTP_XOR_WriteProcessMemory_5ef0 {
  strings:
    $key_5ef0 = { 09 82 [2] 3b a0 [2] 3d 95 [2] 13 95 [2] 2c 89 }

  condition:
    any of them
}