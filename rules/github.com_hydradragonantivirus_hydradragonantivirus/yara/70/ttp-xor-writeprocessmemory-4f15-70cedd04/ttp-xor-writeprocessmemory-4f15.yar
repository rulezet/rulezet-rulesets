rule TTP_XOR_WriteProcessMemory_4f15 {
  strings:
    $key_4f15 = { 18 67 [2] 2a 45 [2] 2c 70 [2] 02 70 [2] 3d 6c }

  condition:
    any of them
}