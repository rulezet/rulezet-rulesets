rule TTP_XOR_WriteProcessMemory_43d2 {
  strings:
    $key_43d2 = { 14 a0 [2] 26 82 [2] 20 b7 [2] 0e b7 [2] 31 ab }

  condition:
    any of them
}