rule TTP_XOR_WriteProcessMemory_67d0 {
  strings:
    $key_67d0 = { 30 a2 [2] 02 80 [2] 04 b5 [2] 2a b5 [2] 15 a9 }

  condition:
    any of them
}