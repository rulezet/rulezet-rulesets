rule TTP_XOR_WriteProcessMemory_9c5c {
  strings:
    $key_9c5c = { cb 2e [2] f9 0c [2] ff 39 [2] d1 39 [2] ee 25 }

  condition:
    any of them
}