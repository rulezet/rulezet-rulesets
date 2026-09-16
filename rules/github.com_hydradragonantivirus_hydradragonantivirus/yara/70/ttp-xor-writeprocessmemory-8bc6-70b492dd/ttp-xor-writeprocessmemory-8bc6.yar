rule TTP_XOR_WriteProcessMemory_8bc6 {
  strings:
    $key_8bc6 = { dc b4 [2] ee 96 [2] e8 a3 [2] c6 a3 [2] f9 bf }

  condition:
    any of them
}