rule TTP_XOR_WriteProcessMemory_8b91 {
  strings:
    $key_8b91 = { dc e3 [2] ee c1 [2] e8 f4 [2] c6 f4 [2] f9 e8 }

  condition:
    any of them
}