rule TTP_XOR_WriteProcessMemory_8b7c {
  strings:
    $key_8b7c = { dc 0e [2] ee 2c [2] e8 19 [2] c6 19 [2] f9 05 }

  condition:
    any of them
}