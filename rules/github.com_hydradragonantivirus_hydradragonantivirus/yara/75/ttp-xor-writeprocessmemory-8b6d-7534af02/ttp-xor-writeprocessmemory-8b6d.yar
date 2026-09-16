rule TTP_XOR_WriteProcessMemory_8b6d {
  strings:
    $key_8b6d = { dc 1f [2] ee 3d [2] e8 08 [2] c6 08 [2] f9 14 }

  condition:
    any of them
}