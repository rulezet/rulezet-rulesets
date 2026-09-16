rule TTP_XOR_WriteProcessMemory_ded2 {
  strings:
    $key_ded2 = { 89 a0 [2] bb 82 [2] bd b7 [2] 93 b7 [2] ac ab }

  condition:
    any of them
}