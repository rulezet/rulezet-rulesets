rule TTP_XOR_WriteProcessMemory_8b4f {
  strings:
    $key_8b4f = { dc 3d [2] ee 1f [2] e8 2a [2] c6 2a [2] f9 36 }

  condition:
    any of them
}