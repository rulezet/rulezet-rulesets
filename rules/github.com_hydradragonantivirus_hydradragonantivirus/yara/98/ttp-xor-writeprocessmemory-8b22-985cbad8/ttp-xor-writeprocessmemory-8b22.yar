rule TTP_XOR_WriteProcessMemory_8b22 {
  strings:
    $key_8b22 = { dc 50 [2] ee 72 [2] e8 47 [2] c6 47 [2] f9 5b }

  condition:
    any of them
}