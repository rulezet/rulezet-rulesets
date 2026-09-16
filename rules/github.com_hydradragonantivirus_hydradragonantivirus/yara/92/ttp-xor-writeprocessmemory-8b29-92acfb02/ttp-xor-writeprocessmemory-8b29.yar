rule TTP_XOR_WriteProcessMemory_8b29 {
  strings:
    $key_8b29 = { dc 5b [2] ee 79 [2] e8 4c [2] c6 4c [2] f9 50 }

  condition:
    any of them
}