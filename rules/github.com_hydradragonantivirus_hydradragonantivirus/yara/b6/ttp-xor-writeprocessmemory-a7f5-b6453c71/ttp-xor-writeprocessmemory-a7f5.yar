rule TTP_XOR_WriteProcessMemory_a7f5 {
  strings:
    $key_a7f5 = { f0 87 [2] c2 a5 [2] c4 90 [2] ea 90 [2] d5 8c }

  condition:
    any of them
}