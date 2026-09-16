rule TTP_XOR_WriteProcessMemory_8b08 {
  strings:
    $key_8b08 = { dc 7a [2] ee 58 [2] e8 6d [2] c6 6d [2] f9 71 }

  condition:
    any of them
}