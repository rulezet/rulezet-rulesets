rule TTP_XOR_WriteProcessMemory_b296 {
  strings:
    $key_b296 = { e5 e4 [2] d7 c6 [2] d1 f3 [2] ff f3 [2] c0 ef }

  condition:
    any of them
}