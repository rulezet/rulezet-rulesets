rule TTP_XOR_WriteProcessMemory_5775 {
  strings:
    $key_5775 = { 00 07 [2] 32 25 [2] 34 10 [2] 1a 10 [2] 25 0c }

  condition:
    any of them
}