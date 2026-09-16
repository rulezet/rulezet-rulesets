rule TTP_XOR_WriteProcessMemory_f8a3 {
  strings:
    $key_f8a3 = { af d1 [2] 9d f3 [2] 9b c6 [2] b5 c6 [2] 8a da }

  condition:
    any of them
}