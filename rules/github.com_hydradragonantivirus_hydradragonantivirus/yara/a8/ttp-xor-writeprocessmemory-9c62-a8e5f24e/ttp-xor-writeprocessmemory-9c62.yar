rule TTP_XOR_WriteProcessMemory_9c62 {
  strings:
    $key_9c62 = { cb 10 [2] f9 32 [2] ff 07 [2] d1 07 [2] ee 1b }

  condition:
    any of them
}