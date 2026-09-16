rule TTP_XOR_WriteProcessMemory_9c55 {
  strings:
    $key_9c55 = { cb 27 [2] f9 05 [2] ff 30 [2] d1 30 [2] ee 2c }

  condition:
    any of them
}