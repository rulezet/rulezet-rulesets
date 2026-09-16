rule TTP_XOR_WriteProcessMemory_37d4 {
  strings:
    $key_37d4 = { 60 a6 [2] 52 84 [2] 54 b1 [2] 7a b1 [2] 45 ad }

  condition:
    any of them
}