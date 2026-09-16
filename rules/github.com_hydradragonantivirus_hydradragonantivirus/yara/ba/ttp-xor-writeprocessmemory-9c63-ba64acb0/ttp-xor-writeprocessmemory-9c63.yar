rule TTP_XOR_WriteProcessMemory_9c63 {
  strings:
    $key_9c63 = { cb 11 [2] f9 33 [2] ff 06 [2] d1 06 [2] ee 1a }

  condition:
    any of them
}