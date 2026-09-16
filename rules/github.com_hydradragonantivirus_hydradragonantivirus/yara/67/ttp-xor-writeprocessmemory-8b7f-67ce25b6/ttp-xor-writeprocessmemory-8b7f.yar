rule TTP_XOR_WriteProcessMemory_8b7f {
  strings:
    $key_8b7f = { dc 0d [2] ee 2f [2] e8 1a [2] c6 1a [2] f9 06 }

  condition:
    any of them
}