rule TTP_XOR_WriteProcessMemory_e6f0 {
  strings:
    $key_e6f0 = { b1 82 [2] 83 a0 [2] 85 95 [2] ab 95 [2] 94 89 }

  condition:
    any of them
}