rule TTP_XOR_WriteProcessMemory_ffc0 {
  strings:
    $key_ffc0 = { a8 b2 [2] 9a 90 [2] 9c a5 [2] b2 a5 [2] 8d b9 }

  condition:
    any of them
}