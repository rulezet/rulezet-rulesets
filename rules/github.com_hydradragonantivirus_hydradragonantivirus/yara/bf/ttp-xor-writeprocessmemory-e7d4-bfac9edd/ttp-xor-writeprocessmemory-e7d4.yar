rule TTP_XOR_WriteProcessMemory_e7d4 {
  strings:
    $key_e7d4 = { b0 a6 [2] 82 84 [2] 84 b1 [2] aa b1 [2] 95 ad }

  condition:
    any of them
}