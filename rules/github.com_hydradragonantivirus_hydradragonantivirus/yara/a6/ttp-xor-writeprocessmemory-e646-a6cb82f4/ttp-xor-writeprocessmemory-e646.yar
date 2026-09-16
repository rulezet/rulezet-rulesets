rule TTP_XOR_WriteProcessMemory_e646 {
  strings:
    $key_e646 = { b1 34 [2] 83 16 [2] 85 23 [2] ab 23 [2] 94 3f }

  condition:
    any of them
}