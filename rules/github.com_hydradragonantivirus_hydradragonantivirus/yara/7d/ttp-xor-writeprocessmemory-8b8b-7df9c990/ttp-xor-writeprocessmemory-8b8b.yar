rule TTP_XOR_WriteProcessMemory_8b8b {
  strings:
    $key_8b8b = { dc f9 [2] ee db [2] e8 ee [2] c6 ee [2] f9 f2 }

  condition:
    any of them
}