rule TTP_XOR_WriteProcessMemory_8bda {
  strings:
    $key_8bda = { dc a8 [2] ee 8a [2] e8 bf [2] c6 bf [2] f9 a3 }

  condition:
    any of them
}