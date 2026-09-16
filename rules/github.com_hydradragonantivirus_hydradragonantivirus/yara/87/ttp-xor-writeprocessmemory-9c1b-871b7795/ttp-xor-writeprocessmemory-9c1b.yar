rule TTP_XOR_WriteProcessMemory_9c1b {
  strings:
    $key_9c1b = { cb 69 [2] f9 4b [2] ff 7e [2] d1 7e [2] ee 62 }

  condition:
    any of them
}