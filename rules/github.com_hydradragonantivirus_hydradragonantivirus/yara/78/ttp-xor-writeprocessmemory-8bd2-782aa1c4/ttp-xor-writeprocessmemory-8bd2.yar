rule TTP_XOR_WriteProcessMemory_8bd2 {
  strings:
    $key_8bd2 = { dc a0 [2] ee 82 [2] e8 b7 [2] c6 b7 [2] f9 ab }

  condition:
    any of them
}