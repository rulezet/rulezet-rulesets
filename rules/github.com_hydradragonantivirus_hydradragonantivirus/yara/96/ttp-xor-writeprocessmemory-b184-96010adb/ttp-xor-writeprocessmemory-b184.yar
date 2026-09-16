rule TTP_XOR_WriteProcessMemory_b184 {
  strings:
    $key_b184 = { e6 f6 [2] d4 d4 [2] d2 e1 [2] fc e1 [2] c3 fd }

  condition:
    any of them
}