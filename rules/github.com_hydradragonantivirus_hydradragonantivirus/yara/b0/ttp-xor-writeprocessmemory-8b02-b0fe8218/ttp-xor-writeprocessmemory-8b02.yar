rule TTP_XOR_WriteProcessMemory_8b02 {
  strings:
    $key_8b02 = { dc 70 [2] ee 52 [2] e8 67 [2] c6 67 [2] f9 7b }

  condition:
    any of them
}