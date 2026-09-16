rule TTP_XOR_WriteProcessMemory_8bcf {
  strings:
    $key_8bcf = { dc bd [2] ee 9f [2] e8 aa [2] c6 aa [2] f9 b6 }

  condition:
    any of them
}