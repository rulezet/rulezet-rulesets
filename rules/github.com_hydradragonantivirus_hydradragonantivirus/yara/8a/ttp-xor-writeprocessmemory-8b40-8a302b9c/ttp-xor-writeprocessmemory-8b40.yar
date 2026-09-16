rule TTP_XOR_WriteProcessMemory_8b40 {
  strings:
    $key_8b40 = { dc 32 [2] ee 10 [2] e8 25 [2] c6 25 [2] f9 39 }

  condition:
    any of them
}