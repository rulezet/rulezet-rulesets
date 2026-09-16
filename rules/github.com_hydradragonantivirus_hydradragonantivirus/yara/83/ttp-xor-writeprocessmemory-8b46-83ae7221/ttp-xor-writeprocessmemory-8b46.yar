rule TTP_XOR_WriteProcessMemory_8b46 {
  strings:
    $key_8b46 = { dc 34 [2] ee 16 [2] e8 23 [2] c6 23 [2] f9 3f }

  condition:
    any of them
}