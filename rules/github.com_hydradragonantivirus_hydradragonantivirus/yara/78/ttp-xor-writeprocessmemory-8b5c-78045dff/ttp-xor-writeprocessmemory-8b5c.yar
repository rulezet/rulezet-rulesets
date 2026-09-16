rule TTP_XOR_WriteProcessMemory_8b5c {
  strings:
    $key_8b5c = { dc 2e [2] ee 0c [2] e8 39 [2] c6 39 [2] f9 25 }

  condition:
    any of them
}