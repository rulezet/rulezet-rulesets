rule TTP_XOR_WriteProcessMemory_8b10 {
  strings:
    $key_8b10 = { dc 62 [2] ee 40 [2] e8 75 [2] c6 75 [2] f9 69 }

  condition:
    any of them
}