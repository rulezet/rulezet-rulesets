rule TTP_XOR_WriteProcessMemory_8b6c {
  strings:
    $key_8b6c = { dc 1e [2] ee 3c [2] e8 09 [2] c6 09 [2] f9 15 }

  condition:
    any of them
}