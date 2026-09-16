rule TTP_XOR_WriteProcessMemory_8b49 {
  strings:
    $key_8b49 = { dc 3b [2] ee 19 [2] e8 2c [2] c6 2c [2] f9 30 }

  condition:
    any of them
}