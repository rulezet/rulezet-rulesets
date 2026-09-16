rule TTP_XOR_WriteProcessMemory_b287 {
  strings:
    $key_b287 = { e5 f5 [2] d7 d7 [2] d1 e2 [2] ff e2 [2] c0 fe }

  condition:
    any of them
}