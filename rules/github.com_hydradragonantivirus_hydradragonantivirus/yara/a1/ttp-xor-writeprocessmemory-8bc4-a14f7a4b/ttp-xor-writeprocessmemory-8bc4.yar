rule TTP_XOR_WriteProcessMemory_8bc4 {
  strings:
    $key_8bc4 = { dc b6 [2] ee 94 [2] e8 a1 [2] c6 a1 [2] f9 bd }

  condition:
    any of them
}