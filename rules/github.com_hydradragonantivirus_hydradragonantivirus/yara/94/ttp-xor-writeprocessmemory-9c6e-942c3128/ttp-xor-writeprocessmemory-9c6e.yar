rule TTP_XOR_WriteProcessMemory_9c6e {
  strings:
    $key_9c6e = { cb 1c [2] f9 3e [2] ff 0b [2] d1 0b [2] ee 17 }

  condition:
    any of them
}