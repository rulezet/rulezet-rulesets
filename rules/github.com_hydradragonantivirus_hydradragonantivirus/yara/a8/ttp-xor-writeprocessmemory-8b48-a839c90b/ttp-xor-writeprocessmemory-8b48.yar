rule TTP_XOR_WriteProcessMemory_8b48 {
  strings:
    $key_8b48 = { dc 3a [2] ee 18 [2] e8 2d [2] c6 2d [2] f9 31 }

  condition:
    any of them
}