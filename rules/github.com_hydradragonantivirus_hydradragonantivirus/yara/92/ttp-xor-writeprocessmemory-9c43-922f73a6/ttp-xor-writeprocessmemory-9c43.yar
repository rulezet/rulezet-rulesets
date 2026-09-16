rule TTP_XOR_WriteProcessMemory_9c43 {
  strings:
    $key_9c43 = { cb 31 [2] f9 13 [2] ff 26 [2] d1 26 [2] ee 3a }

  condition:
    any of them
}