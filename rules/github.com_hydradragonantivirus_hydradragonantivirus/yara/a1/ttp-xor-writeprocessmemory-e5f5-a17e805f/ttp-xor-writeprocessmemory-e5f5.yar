rule TTP_XOR_WriteProcessMemory_e5f5 {
  strings:
    $key_e5f5 = { b2 87 [2] 80 a5 [2] 86 90 [2] a8 90 [2] 97 8c }

  condition:
    any of them
}