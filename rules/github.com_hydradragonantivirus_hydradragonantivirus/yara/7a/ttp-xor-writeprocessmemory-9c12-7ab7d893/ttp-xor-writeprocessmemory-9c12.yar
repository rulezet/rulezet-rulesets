rule TTP_XOR_WriteProcessMemory_9c12 {
  strings:
    $key_9c12 = { cb 60 [2] f9 42 [2] ff 77 [2] d1 77 [2] ee 6b }

  condition:
    any of them
}