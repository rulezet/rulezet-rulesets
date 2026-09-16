rule TTP_XOR_WriteProcessMemory_8b93 {
  strings:
    $key_8b93 = { dc e1 [2] ee c3 [2] e8 f6 [2] c6 f6 [2] f9 ea }

  condition:
    any of them
}