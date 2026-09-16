rule TTP_XOR_WriteProcessMemory_8b34 {
  strings:
    $key_8b34 = { dc 46 [2] ee 64 [2] e8 51 [2] c6 51 [2] f9 4d }

  condition:
    any of them
}