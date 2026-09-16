rule TTP_XOR_WriteProcessMemory_e7a3 {
  strings:
    $key_e7a3 = { b0 d1 [2] 82 f3 [2] 84 c6 [2] aa c6 [2] 95 da }

  condition:
    any of them
}