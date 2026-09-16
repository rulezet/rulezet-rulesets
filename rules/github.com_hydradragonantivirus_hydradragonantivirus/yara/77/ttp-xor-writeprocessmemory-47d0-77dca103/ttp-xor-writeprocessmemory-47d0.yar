rule TTP_XOR_WriteProcessMemory_47d0 {
  strings:
    $key_47d0 = { 10 a2 [2] 22 80 [2] 24 b5 [2] 0a b5 [2] 35 a9 }

  condition:
    any of them
}