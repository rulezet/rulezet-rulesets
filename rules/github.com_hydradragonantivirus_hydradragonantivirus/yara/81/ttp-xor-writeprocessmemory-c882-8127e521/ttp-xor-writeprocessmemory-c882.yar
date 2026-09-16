rule TTP_XOR_WriteProcessMemory_c882 {
  strings:
    $key_c882 = { 9f f0 [2] ad d2 [2] ab e7 [2] 85 e7 [2] ba fb }

  condition:
    any of them
}