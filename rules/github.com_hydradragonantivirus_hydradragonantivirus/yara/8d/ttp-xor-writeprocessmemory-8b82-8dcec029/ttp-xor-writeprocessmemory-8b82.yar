rule TTP_XOR_WriteProcessMemory_8b82 {
  strings:
    $key_8b82 = { dc f0 [2] ee d2 [2] e8 e7 [2] c6 e7 [2] f9 fb }

  condition:
    any of them
}