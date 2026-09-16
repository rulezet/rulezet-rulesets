rule TTP_XOR_WriteProcessMemory_9c4b {
  strings:
    $key_9c4b = { cb 39 [2] f9 1b [2] ff 2e [2] d1 2e [2] ee 32 }

  condition:
    any of them
}