rule TTP_XOR_WriteProcessMemory_e795 {
  strings:
    $key_e795 = { b0 e7 [2] 82 c5 [2] 84 f0 [2] aa f0 [2] 95 ec }

  condition:
    any of them
}