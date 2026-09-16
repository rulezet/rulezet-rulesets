rule TTP_XOR_WriteProcessMemory_8b80 {
  strings:
    $key_8b80 = { dc f2 [2] ee d0 [2] e8 e5 [2] c6 e5 [2] f9 f9 }

  condition:
    any of them
}