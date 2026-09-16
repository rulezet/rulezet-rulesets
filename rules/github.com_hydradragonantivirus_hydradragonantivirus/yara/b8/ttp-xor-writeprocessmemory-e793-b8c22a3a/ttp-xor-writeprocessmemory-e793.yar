rule TTP_XOR_WriteProcessMemory_e793 {
  strings:
    $key_e793 = { b0 e1 [2] 82 c3 [2] 84 f6 [2] aa f6 [2] 95 ea }

  condition:
    any of them
}