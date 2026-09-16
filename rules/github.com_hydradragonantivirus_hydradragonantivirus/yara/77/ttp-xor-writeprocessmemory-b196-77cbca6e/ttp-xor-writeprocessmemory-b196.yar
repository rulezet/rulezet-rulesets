rule TTP_XOR_WriteProcessMemory_b196 {
  strings:
    $key_b196 = { e6 e4 [2] d4 c6 [2] d2 f3 [2] fc f3 [2] c3 ef }

  condition:
    any of them
}