rule TTP_XOR_WriteProcessMemory_8bd4 {
  strings:
    $key_8bd4 = { dc a6 [2] ee 84 [2] e8 b1 [2] c6 b1 [2] f9 ad }

  condition:
    any of them
}