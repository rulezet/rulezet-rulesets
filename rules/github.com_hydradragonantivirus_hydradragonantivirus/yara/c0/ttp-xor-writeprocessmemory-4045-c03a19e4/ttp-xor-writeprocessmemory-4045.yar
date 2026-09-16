rule TTP_XOR_WriteProcessMemory_4045 {
  strings:
    $key_4045 = { 17 37 [2] 25 15 [2] 23 20 [2] 0d 20 [2] 32 3c }

  condition:
    any of them
}