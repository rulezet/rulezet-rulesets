rule TTP_XOR_WriteProcessMemory_8b77 {
  strings:
    $key_8b77 = { dc 05 [2] ee 27 [2] e8 12 [2] c6 12 [2] f9 0e }

  condition:
    any of them
}