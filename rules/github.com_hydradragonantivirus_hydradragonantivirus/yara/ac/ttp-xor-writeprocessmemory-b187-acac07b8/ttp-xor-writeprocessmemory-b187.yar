rule TTP_XOR_WriteProcessMemory_b187 {
  strings:
    $key_b187 = { e6 f5 [2] d4 d7 [2] d2 e2 [2] fc e2 [2] c3 fe }

  condition:
    any of them
}