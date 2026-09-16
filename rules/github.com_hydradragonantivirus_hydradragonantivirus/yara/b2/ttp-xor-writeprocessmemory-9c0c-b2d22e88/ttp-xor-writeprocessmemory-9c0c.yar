rule TTP_XOR_WriteProcessMemory_9c0c {
  strings:
    $key_9c0c = { cb 7e [2] f9 5c [2] ff 69 [2] d1 69 [2] ee 75 }

  condition:
    any of them
}