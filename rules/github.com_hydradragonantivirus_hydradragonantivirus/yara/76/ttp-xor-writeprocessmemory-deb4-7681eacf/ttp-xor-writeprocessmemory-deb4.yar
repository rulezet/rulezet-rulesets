rule TTP_XOR_WriteProcessMemory_deb4 {
  strings:
    $key_deb4 = { 89 c6 [2] bb e4 [2] bd d1 [2] 93 d1 [2] ac cd }

  condition:
    any of them
}