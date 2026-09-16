rule TTP_XOR_WriteProcessMemory_8b13 {
  strings:
    $key_8b13 = { dc 61 [2] ee 43 [2] e8 76 [2] c6 76 [2] f9 6a }

  condition:
    any of them
}