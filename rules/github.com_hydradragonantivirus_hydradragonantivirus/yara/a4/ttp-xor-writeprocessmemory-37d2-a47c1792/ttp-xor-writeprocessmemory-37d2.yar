rule TTP_XOR_WriteProcessMemory_37d2 {
  strings:
    $key_37d2 = { 60 a0 [2] 52 82 [2] 54 b7 [2] 7a b7 [2] 45 ab }

  condition:
    any of them
}