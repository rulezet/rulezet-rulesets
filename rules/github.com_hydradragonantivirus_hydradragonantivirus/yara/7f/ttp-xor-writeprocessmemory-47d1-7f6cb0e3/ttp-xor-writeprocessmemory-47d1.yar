rule TTP_XOR_WriteProcessMemory_47d1 {
  strings:
    $key_47d1 = { 10 a3 [2] 22 81 [2] 24 b4 [2] 0a b4 [2] 35 a8 }

  condition:
    any of them
}