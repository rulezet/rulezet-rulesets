rule TTP_XOR_WriteProcessMemory_8b72 {
  strings:
    $key_8b72 = { dc 00 [2] ee 22 [2] e8 17 [2] c6 17 [2] f9 0b }

  condition:
    any of them
}