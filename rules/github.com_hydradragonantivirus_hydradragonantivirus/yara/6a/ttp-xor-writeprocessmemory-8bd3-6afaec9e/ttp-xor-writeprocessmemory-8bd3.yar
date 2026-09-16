rule TTP_XOR_WriteProcessMemory_8bd3 {
  strings:
    $key_8bd3 = { dc a1 [2] ee 83 [2] e8 b6 [2] c6 b6 [2] f9 aa }

  condition:
    any of them
}