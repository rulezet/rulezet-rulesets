rule TTP_XOR_WriteProcessMemory_e7e0 {
  strings:
    $key_e7e0 = { b0 92 [2] 82 b0 [2] 84 85 [2] aa 85 [2] 95 99 }

  condition:
    any of them
}