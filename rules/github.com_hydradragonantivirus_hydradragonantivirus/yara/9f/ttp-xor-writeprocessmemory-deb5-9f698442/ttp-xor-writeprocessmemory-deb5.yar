rule TTP_XOR_WriteProcessMemory_deb5 {
  strings:
    $key_deb5 = { 89 c7 [2] bb e5 [2] bd d0 [2] 93 d0 [2] ac cc }

  condition:
    any of them
}