rule TTP_XOR_WriteProcessMemory_8bdd {
  strings:
    $key_8bdd = { dc af [2] ee 8d [2] e8 b8 [2] c6 b8 [2] f9 a4 }

  condition:
    any of them
}