rule TTP_XOR_WriteProcessMemory_9c1e {
  strings:
    $key_9c1e = { cb 6c [2] f9 4e [2] ff 7b [2] d1 7b [2] ee 67 }

  condition:
    any of them
}