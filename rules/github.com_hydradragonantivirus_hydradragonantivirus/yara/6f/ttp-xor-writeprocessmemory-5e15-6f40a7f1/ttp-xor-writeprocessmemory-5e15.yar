rule TTP_XOR_WriteProcessMemory_5e15 {
  strings:
    $key_5e15 = { 09 67 [2] 3b 45 [2] 3d 70 [2] 13 70 [2] 2c 6c }

  condition:
    any of them
}