rule TTP_XOR_WriteProcessMemory_8b3b {
  strings:
    $key_8b3b = { dc 49 [2] ee 6b [2] e8 5e [2] c6 5e [2] f9 42 }

  condition:
    any of them
}