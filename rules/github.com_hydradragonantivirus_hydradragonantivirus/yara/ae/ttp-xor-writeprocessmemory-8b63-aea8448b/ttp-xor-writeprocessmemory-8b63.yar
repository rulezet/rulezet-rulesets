rule TTP_XOR_WriteProcessMemory_8b63 {
  strings:
    $key_8b63 = { dc 11 [2] ee 33 [2] e8 06 [2] c6 06 [2] f9 1a }

  condition:
    any of them
}