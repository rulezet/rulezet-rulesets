rule TTP_XOR_WriteProcessMemory_8bd7 {
  strings:
    $key_8bd7 = { dc a5 [2] ee 87 [2] e8 b2 [2] c6 b2 [2] f9 ae }

  condition:
    any of them
}