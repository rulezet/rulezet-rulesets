rule TTP_XOR_WriteProcessMemory_5ee7 {
  strings:
    $key_5ee7 = { 09 95 [2] 3b b7 [2] 3d 82 [2] 13 82 [2] 2c 9e }

  condition:
    any of them
}