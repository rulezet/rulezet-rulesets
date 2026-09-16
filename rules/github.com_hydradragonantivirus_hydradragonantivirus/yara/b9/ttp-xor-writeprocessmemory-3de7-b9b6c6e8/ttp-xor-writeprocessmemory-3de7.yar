rule TTP_XOR_WriteProcessMemory_3de7 {
  strings:
    $key_3de7 = { 6a 95 [2] 58 b7 [2] 5e 82 [2] 70 82 [2] 4f 9e }

  condition:
    any of them
}