rule TTP_XOR_WriteProcessMemory_e7e2 {
  strings:
    $key_e7e2 = { b0 90 [2] 82 b2 [2] 84 87 [2] aa 87 [2] 95 9b }

  condition:
    any of them
}