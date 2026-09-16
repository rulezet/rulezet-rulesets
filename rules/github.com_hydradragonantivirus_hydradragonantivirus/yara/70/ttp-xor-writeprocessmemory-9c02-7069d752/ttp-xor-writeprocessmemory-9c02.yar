rule TTP_XOR_WriteProcessMemory_9c02 {
  strings:
    $key_9c02 = { cb 70 [2] f9 52 [2] ff 67 [2] d1 67 [2] ee 7b }

  condition:
    any of them
}