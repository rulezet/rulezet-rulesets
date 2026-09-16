rule TTP_XOR_WriteProcessMemory_8b6b {
  strings:
    $key_8b6b = { dc 19 [2] ee 3b [2] e8 0e [2] c6 0e [2] f9 12 }

  condition:
    any of them
}