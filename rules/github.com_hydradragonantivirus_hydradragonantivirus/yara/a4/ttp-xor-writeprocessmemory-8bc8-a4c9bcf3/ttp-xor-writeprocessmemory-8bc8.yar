rule TTP_XOR_WriteProcessMemory_8bc8 {
  strings:
    $key_8bc8 = { dc ba [2] ee 98 [2] e8 ad [2] c6 ad [2] f9 b1 }

  condition:
    any of them
}