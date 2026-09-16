rule TTP_XOR_WriteProcessMemory_9cf9 {
  strings:
    $key_9cf9 = { cb 8b [2] f9 a9 [2] ff 9c [2] d1 9c [2] ee 80 }

  condition:
    any of them
}