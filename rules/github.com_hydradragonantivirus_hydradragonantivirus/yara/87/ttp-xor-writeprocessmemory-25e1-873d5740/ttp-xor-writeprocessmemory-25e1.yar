rule TTP_XOR_WriteProcessMemory_25e1 {
  strings:
    $key_25e1 = { 72 93 [2] 40 b1 [2] 46 84 [2] 68 84 [2] 57 98 }

  condition:
    any of them
}