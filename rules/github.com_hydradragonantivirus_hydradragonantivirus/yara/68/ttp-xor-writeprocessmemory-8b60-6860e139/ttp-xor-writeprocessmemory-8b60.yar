rule TTP_XOR_WriteProcessMemory_8b60 {
  strings:
    $key_8b60 = { dc 12 [2] ee 30 [2] e8 05 [2] c6 05 [2] f9 19 }

  condition:
    any of them
}