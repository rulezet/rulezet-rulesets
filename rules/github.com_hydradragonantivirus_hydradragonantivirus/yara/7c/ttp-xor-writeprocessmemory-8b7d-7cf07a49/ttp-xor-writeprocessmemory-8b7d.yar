rule TTP_XOR_WriteProcessMemory_8b7d {
  strings:
    $key_8b7d = { dc 0f [2] ee 2d [2] e8 18 [2] c6 18 [2] f9 04 }

  condition:
    any of them
}