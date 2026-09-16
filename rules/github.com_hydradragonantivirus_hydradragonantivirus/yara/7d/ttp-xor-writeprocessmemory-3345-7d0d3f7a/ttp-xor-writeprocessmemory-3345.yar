rule TTP_XOR_WriteProcessMemory_3345 {
  strings:
    $key_3345 = { 64 37 [2] 56 15 [2] 50 20 [2] 7e 20 [2] 41 3c }

  condition:
    any of them
}