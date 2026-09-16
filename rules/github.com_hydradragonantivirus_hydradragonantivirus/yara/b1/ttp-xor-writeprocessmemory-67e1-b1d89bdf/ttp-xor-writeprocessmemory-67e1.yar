rule TTP_XOR_WriteProcessMemory_67e1 {
  strings:
    $key_67e1 = { 30 93 [2] 02 b1 [2] 04 84 [2] 2a 84 [2] 15 98 }

  condition:
    any of them
}