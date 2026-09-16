rule TTP_XOR_WriteProcessMemory_4075 {
  strings:
    $key_4075 = { 17 07 [2] 25 25 [2] 23 10 [2] 0d 10 [2] 32 0c }

  condition:
    any of them
}