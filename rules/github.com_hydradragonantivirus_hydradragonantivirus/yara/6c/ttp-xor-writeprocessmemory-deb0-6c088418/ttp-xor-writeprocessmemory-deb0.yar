rule TTP_XOR_WriteProcessMemory_deb0 {
  strings:
    $key_deb0 = { 89 c2 [2] bb e0 [2] bd d5 [2] 93 d5 [2] ac c9 }

  condition:
    any of them
}