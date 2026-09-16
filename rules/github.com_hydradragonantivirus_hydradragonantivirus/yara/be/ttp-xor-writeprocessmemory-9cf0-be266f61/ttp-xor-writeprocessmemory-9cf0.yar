rule TTP_XOR_WriteProcessMemory_9cf0 {
  strings:
    $key_9cf0 = { cb 82 [2] f9 a0 [2] ff 95 [2] d1 95 [2] ee 89 }

  condition:
    any of them
}