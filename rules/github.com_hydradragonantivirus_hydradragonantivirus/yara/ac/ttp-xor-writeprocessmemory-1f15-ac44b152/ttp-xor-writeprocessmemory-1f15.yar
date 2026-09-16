rule TTP_XOR_WriteProcessMemory_1f15 {
  strings:
    $key_1f15 = { 48 67 [2] 7a 45 [2] 7c 70 [2] 52 70 [2] 6d 6c }

  condition:
    any of them
}