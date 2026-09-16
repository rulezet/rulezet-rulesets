rule TTP_XOR_WriteProcessMemory_8b31 {
  strings:
    $key_8b31 = { dc 43 [2] ee 61 [2] e8 54 [2] c6 54 [2] f9 48 }

  condition:
    any of them
}