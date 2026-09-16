rule TTP_XOR_WriteProcessMemory_ffc5 {
  strings:
    $key_ffc5 = { a8 b7 [2] 9a 95 [2] 9c a0 [2] b2 a0 [2] 8d bc }

  condition:
    any of them
}