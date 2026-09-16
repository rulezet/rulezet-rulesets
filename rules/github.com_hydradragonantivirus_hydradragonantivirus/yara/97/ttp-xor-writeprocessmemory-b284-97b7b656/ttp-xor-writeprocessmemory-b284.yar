rule TTP_XOR_WriteProcessMemory_b284 {
  strings:
    $key_b284 = { e5 f6 [2] d7 d4 [2] d1 e1 [2] ff e1 [2] c0 fd }

  condition:
    any of them
}