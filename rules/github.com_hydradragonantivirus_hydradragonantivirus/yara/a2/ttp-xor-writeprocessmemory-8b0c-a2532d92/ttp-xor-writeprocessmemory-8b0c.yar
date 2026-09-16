rule TTP_XOR_WriteProcessMemory_8b0c {
  strings:
    $key_8b0c = { dc 7e [2] ee 5c [2] e8 69 [2] c6 69 [2] f9 75 }

  condition:
    any of them
}