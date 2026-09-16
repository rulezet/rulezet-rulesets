rule TTP_XOR_WriteProcessMemory_8b17 {
  strings:
    $key_8b17 = { dc 65 [2] ee 47 [2] e8 72 [2] c6 72 [2] f9 6e }

  condition:
    any of them
}