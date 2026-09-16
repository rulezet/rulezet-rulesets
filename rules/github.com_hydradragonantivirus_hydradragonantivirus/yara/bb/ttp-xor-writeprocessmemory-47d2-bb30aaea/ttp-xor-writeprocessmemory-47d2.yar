rule TTP_XOR_WriteProcessMemory_47d2 {
  strings:
    $key_47d2 = { 10 a0 [2] 22 82 [2] 24 b7 [2] 0a b7 [2] 35 ab }

  condition:
    any of them
}