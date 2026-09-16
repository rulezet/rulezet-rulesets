rule TTP_XOR_WriteProcessMemory_f8d1 {
  strings:
    $key_f8d1 = { af a3 [2] 9d 81 [2] 9b b4 [2] b5 b4 [2] 8a a8 }

  condition:
    any of them
}