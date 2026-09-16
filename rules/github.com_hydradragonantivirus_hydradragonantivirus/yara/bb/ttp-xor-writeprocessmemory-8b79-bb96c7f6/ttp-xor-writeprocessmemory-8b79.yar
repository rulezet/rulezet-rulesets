rule TTP_XOR_WriteProcessMemory_8b79 {
  strings:
    $key_8b79 = { dc 0b [2] ee 29 [2] e8 1c [2] c6 1c [2] f9 00 }

  condition:
    any of them
}