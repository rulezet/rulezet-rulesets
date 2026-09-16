rule TTP_XOR_WriteProcessMemory_8b4c {
  strings:
    $key_8b4c = { dc 3e [2] ee 1c [2] e8 29 [2] c6 29 [2] f9 35 }

  condition:
    any of them
}