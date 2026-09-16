rule TTP_XOR_WriteProcessMemory_8b6f {
  strings:
    $key_8b6f = { dc 1d [2] ee 3f [2] e8 0a [2] c6 0a [2] f9 16 }

  condition:
    any of them
}