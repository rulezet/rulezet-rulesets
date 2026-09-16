rule TTP_XOR_WriteProcessMemory_8b09 {
  strings:
    $key_8b09 = { dc 7b [2] ee 59 [2] e8 6c [2] c6 6c [2] f9 70 }

  condition:
    any of them
}