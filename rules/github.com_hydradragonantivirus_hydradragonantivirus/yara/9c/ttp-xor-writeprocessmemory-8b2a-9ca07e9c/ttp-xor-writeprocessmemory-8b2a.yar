rule TTP_XOR_WriteProcessMemory_8b2a {
  strings:
    $key_8b2a = { dc 58 [2] ee 7a [2] e8 4f [2] c6 4f [2] f9 53 }

  condition:
    any of them
}