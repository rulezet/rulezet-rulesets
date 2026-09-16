rule TTP_XOR_WriteProcessMemory_e7c0 {
  strings:
    $key_e7c0 = { b0 b2 [2] 82 90 [2] 84 a5 [2] aa a5 [2] 95 b9 }

  condition:
    any of them
}