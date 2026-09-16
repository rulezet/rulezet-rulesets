rule TTP_XOR_WriteProcessMemory_8b19 {
  strings:
    $key_8b19 = { dc 6b [2] ee 49 [2] e8 7c [2] c6 7c [2] f9 60 }

  condition:
    any of them
}