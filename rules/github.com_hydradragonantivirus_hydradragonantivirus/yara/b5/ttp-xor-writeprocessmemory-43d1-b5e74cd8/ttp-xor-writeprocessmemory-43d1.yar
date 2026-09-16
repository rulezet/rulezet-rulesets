rule TTP_XOR_WriteProcessMemory_43d1 {
  strings:
    $key_43d1 = { 14 a3 [2] 26 81 [2] 20 b4 [2] 0e b4 [2] 31 a8 }

  condition:
    any of them
}