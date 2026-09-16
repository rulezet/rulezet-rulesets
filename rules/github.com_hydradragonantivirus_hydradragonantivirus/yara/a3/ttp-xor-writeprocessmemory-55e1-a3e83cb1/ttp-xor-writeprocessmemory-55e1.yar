rule TTP_XOR_WriteProcessMemory_55e1 {
  strings:
    $key_55e1 = { 02 93 [2] 30 b1 [2] 36 84 [2] 18 84 [2] 27 98 }

  condition:
    any of them
}