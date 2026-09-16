rule TTP_XOR_WriteProcessMemory_e792 {
  strings:
    $key_e792 = { b0 e0 [2] 82 c2 [2] 84 f7 [2] aa f7 [2] 95 eb }

  condition:
    any of them
}