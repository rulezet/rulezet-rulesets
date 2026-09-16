rule TTP_XOR_WriteProcessMemory_43d0 {
  strings:
    $key_43d0 = { 14 a2 [2] 26 80 [2] 20 b5 [2] 0e b5 [2] 31 a9 }

  condition:
    any of them
}