rule TTP_XOR_WriteProcessMemory_8bd1 {
  strings:
    $key_8bd1 = { dc a3 [2] ee 81 [2] e8 b4 [2] c6 b4 [2] f9 a8 }

  condition:
    any of them
}