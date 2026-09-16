rule TTP_XOR_WriteProcessMemory_ded6 {
  strings:
    $key_ded6 = { 89 a4 [2] bb 86 [2] bd b3 [2] 93 b3 [2] ac af }

  condition:
    any of them
}