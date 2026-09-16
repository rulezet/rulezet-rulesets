rule TTP_XOR_WriteProcessMemory_e6f5 {
  strings:
    $key_e6f5 = { b1 87 [2] 83 a5 [2] 85 90 [2] ab 90 [2] 94 8c }

  condition:
    any of them
}