rule TTP_XOR_WriteProcessMemory_8b28 {
  strings:
    $key_8b28 = { dc 5a [2] ee 78 [2] e8 4d [2] c6 4d [2] f9 51 }

  condition:
    any of them
}