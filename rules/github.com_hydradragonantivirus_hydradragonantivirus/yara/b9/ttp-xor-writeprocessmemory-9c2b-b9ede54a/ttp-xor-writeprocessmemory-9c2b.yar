rule TTP_XOR_WriteProcessMemory_9c2b {
  strings:
    $key_9c2b = { cb 59 [2] f9 7b [2] ff 4e [2] d1 4e [2] ee 52 }

  condition:
    any of them
}