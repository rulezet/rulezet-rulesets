rule TTP_XOR_WriteProcessMemory_5f15 {
  strings:
    $key_5f15 = { 08 67 [2] 3a 45 [2] 3c 70 [2] 12 70 [2] 2d 6c }

  condition:
    any of them
}