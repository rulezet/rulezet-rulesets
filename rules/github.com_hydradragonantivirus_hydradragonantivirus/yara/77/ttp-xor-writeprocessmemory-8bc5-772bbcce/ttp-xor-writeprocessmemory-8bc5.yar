rule TTP_XOR_WriteProcessMemory_8bc5 {
  strings:
    $key_8bc5 = { dc b7 [2] ee 95 [2] e8 a0 [2] c6 a0 [2] f9 bc }

  condition:
    any of them
}