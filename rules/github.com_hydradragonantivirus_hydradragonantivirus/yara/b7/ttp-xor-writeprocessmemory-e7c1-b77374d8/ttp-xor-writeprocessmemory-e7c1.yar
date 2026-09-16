rule TTP_XOR_WriteProcessMemory_e7c1 {
  strings:
    $key_e7c1 = { b0 b3 [2] 82 91 [2] 84 a4 [2] aa a4 [2] 95 b8 }

  condition:
    any of them
}