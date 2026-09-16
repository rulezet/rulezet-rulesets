rule TTP_XOR_WriteProcessMemory_47d4 {
  strings:
    $key_47d4 = { 10 a6 [2] 22 84 [2] 24 b1 [2] 0a b1 [2] 35 ad }

  condition:
    any of them
}