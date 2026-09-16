rule TTP_XOR_WriteProcessMemory_53c1 {
  strings:
    $key_53c1 = { 04 b3 [2] 36 91 [2] 30 a4 [2] 1e a4 [2] 21 b8 }

  condition:
    any of them
}