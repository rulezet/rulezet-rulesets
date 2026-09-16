rule TTP_XOR_WriteProcessMemory_9c41 {
  strings:
    $key_9c41 = { cb 33 [2] f9 11 [2] ff 24 [2] d1 24 [2] ee 38 }

  condition:
    any of them
}