rule TTP_XOR_WriteProcessMemory_8b11 {
  strings:
    $key_8b11 = { dc 63 [2] ee 41 [2] e8 74 [2] c6 74 [2] f9 68 }

  condition:
    any of them
}