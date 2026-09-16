rule TTP_XOR_WriteProcessMemory_8b4b {
  strings:
    $key_8b4b = { dc 39 [2] ee 1b [2] e8 2e [2] c6 2e [2] f9 32 }

  condition:
    any of them
}