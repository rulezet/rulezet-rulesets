rule TTP_XOR_WriteProcessMemory_a2f5 {
  strings:
    $key_a2f5 = { f5 87 [2] c7 a5 [2] c1 90 [2] ef 90 [2] d0 8c }

  condition:
    any of them
}