rule TTP_XOR_WriteProcessMemory_8b06 {
  strings:
    $key_8b06 = { dc 74 [2] ee 56 [2] e8 63 [2] c6 63 [2] f9 7f }

  condition:
    any of them
}