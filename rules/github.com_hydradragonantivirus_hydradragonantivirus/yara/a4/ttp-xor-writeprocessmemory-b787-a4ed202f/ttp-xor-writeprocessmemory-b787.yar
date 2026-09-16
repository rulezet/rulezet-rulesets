rule TTP_XOR_WriteProcessMemory_b787 {
  strings:
    $key_b787 = { e0 f5 [2] d2 d7 [2] d4 e2 [2] fa e2 [2] c5 fe }

  condition:
    any of them
}