rule TTP_XOR_WriteProcessMemory_9cf3 {
  strings:
    $key_9cf3 = { cb 81 [2] f9 a3 [2] ff 96 [2] d1 96 [2] ee 8a }

  condition:
    any of them
}