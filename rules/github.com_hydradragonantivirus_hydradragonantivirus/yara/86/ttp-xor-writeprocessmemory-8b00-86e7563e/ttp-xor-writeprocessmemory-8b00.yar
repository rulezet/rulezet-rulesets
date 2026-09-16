rule TTP_XOR_WriteProcessMemory_8b00 {
  strings:
    $key_8b00 = { dc 72 [2] ee 50 [2] e8 65 [2] c6 65 [2] f9 79 }

  condition:
    any of them
}