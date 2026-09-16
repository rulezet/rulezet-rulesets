rule TTP_XOR_WriteProcessMemory_8b14 {
  strings:
    $key_8b14 = { dc 66 [2] ee 44 [2] e8 71 [2] c6 71 [2] f9 6d }

  condition:
    any of them
}