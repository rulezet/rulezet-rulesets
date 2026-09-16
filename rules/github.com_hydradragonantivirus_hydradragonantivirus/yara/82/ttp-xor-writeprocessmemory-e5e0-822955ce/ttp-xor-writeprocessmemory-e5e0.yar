rule TTP_XOR_WriteProcessMemory_e5e0 {
  strings:
    $key_e5e0 = { b2 92 [2] 80 b0 [2] 86 85 [2] a8 85 [2] 97 99 }

  condition:
    any of them
}