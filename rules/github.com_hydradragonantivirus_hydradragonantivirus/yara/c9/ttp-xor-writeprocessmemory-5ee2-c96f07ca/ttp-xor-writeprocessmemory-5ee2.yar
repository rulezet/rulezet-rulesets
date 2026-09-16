rule TTP_XOR_WriteProcessMemory_5ee2 {
  strings:
    $key_5ee2 = { 09 90 [2] 3b b2 [2] 3d 87 [2] 13 87 [2] 2c 9b }

  condition:
    any of them
}