rule TTP_XOR_WriteProcessMemory_8b6a {
  strings:
    $key_8b6a = { dc 18 [2] ee 3a [2] e8 0f [2] c6 0f [2] f9 13 }

  condition:
    any of them
}