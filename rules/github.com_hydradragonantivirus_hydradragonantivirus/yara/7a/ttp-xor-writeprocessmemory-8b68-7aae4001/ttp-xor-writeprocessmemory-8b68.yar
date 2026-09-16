rule TTP_XOR_WriteProcessMemory_8b68 {
  strings:
    $key_8b68 = { dc 1a [2] ee 38 [2] e8 0d [2] c6 0d [2] f9 11 }

  condition:
    any of them
}