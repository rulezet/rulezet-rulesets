rule TTP_XOR_WriteProcessMemory_e7a4 {
  strings:
    $key_e7a4 = { b0 d6 [2] 82 f4 [2] 84 c1 [2] aa c1 [2] 95 dd }

  condition:
    any of them
}