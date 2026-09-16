rule TTP_XOR_WriteProcessMemory_8b30 {
  strings:
    $key_8b30 = { dc 42 [2] ee 60 [2] e8 55 [2] c6 55 [2] f9 49 }

  condition:
    any of them
}