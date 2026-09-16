rule TTP_XOR_WriteProcessMemory_f8a0 {
  strings:
    $key_f8a0 = { af d2 [2] 9d f0 [2] 9b c5 [2] b5 c5 [2] 8a d9 }

  condition:
    any of them
}