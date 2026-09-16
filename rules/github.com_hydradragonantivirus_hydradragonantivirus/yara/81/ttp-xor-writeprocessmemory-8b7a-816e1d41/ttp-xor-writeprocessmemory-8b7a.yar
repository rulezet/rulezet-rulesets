rule TTP_XOR_WriteProcessMemory_8b7a {
  strings:
    $key_8b7a = { dc 08 [2] ee 2a [2] e8 1f [2] c6 1f [2] f9 03 }

  condition:
    any of them
}