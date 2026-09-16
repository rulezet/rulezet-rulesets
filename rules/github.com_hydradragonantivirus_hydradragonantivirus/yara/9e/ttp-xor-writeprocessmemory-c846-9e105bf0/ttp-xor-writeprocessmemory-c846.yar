rule TTP_XOR_WriteProcessMemory_c846 {
  strings:
    $key_c846 = { 9f 34 [2] ad 16 [2] ab 23 [2] 85 23 [2] ba 3f }

  condition:
    any of them
}