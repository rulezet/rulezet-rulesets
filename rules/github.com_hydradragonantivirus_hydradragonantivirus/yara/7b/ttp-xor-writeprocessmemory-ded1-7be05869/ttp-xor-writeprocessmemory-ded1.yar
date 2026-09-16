rule TTP_XOR_WriteProcessMemory_ded1 {
  strings:
    $key_ded1 = { 89 a3 [2] bb 81 [2] bd b4 [2] 93 b4 [2] ac a8 }

  condition:
    any of them
}