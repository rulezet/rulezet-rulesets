rule TTP_XOR_WriteProcessMemory_53e1 {
  strings:
    $key_53e1 = { 04 93 [2] 36 b1 [2] 30 84 [2] 1e 84 [2] 21 98 }

  condition:
    any of them
}