rule TTP_XOR_WriteProcessMemory_b181 {
  strings:
    $key_b181 = { e6 f3 [2] d4 d1 [2] d2 e4 [2] fc e4 [2] c3 f8 }

  condition:
    any of them
}