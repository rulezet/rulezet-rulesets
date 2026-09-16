rule TTP_XOR_WriteProcessMemory_9c29 {
  strings:
    $key_9c29 = { cb 5b [2] f9 79 [2] ff 4c [2] d1 4c [2] ee 50 }

  condition:
    any of them
}