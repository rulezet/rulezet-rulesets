rule TTP_XOR_WriteProcessMemory_b293 {
  strings:
    $key_b293 = { e5 e1 [2] d7 c3 [2] d1 f6 [2] ff f6 [2] c0 ea }

  condition:
    any of them
}