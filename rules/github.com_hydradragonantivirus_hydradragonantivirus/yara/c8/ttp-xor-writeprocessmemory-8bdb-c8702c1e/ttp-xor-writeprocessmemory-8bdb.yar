rule TTP_XOR_WriteProcessMemory_8bdb {
  strings:
    $key_8bdb = { dc a9 [2] ee 8b [2] e8 be [2] c6 be [2] f9 a2 }

  condition:
    any of them
}