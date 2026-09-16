rule TTP_XOR_WriteProcessMemory_45f0 {
  strings:
    $key_45f0 = { 12 82 [2] 20 a0 [2] 26 95 [2] 08 95 [2] 37 89 }

  condition:
    any of them
}