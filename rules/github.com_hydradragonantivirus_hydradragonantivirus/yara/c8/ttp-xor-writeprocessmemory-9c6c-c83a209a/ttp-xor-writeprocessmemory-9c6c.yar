rule TTP_XOR_WriteProcessMemory_9c6c {
  strings:
    $key_9c6c = { cb 1e [2] f9 3c [2] ff 09 [2] d1 09 [2] ee 15 }

  condition:
    any of them
}