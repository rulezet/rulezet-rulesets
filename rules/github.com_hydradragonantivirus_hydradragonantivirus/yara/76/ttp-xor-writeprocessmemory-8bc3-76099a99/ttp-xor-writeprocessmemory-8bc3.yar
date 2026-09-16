rule TTP_XOR_WriteProcessMemory_8bc3 {
  strings:
    $key_8bc3 = { dc b1 [2] ee 93 [2] e8 a6 [2] c6 a6 [2] f9 ba }

  condition:
    any of them
}