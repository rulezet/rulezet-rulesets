rule TTP_XOR_WriteProcessMemory_8b73 {
  strings:
    $key_8b73 = { dc 01 [2] ee 23 [2] e8 16 [2] c6 16 [2] f9 0a }

  condition:
    any of them
}