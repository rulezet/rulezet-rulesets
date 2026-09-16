rule TTP_XOR_WriteProcessMemory_9c3b {
  strings:
    $key_9c3b = { cb 49 [2] f9 6b [2] ff 5e [2] d1 5e [2] ee 42 }

  condition:
    any of them
}