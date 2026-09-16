rule TTP_XOR_WriteProcessMemory_15c1 {
  strings:
    $key_15c1 = { 42 b3 [2] 70 91 [2] 76 a4 [2] 58 a4 [2] 67 b8 }

  condition:
    any of them
}