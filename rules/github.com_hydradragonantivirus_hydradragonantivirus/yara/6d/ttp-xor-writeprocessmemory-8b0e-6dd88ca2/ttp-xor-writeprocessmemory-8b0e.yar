rule TTP_XOR_WriteProcessMemory_8b0e {
  strings:
    $key_8b0e = { dc 7c [2] ee 5e [2] e8 6b [2] c6 6b [2] f9 77 }

  condition:
    any of them
}