rule TTP_XOR_WriteProcessMemory_8bca {
  strings:
    $key_8bca = { dc b8 [2] ee 9a [2] e8 af [2] c6 af [2] f9 b3 }

  condition:
    any of them
}