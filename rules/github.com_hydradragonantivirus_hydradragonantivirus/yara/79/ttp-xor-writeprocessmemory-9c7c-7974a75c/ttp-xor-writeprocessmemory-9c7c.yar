rule TTP_XOR_WriteProcessMemory_9c7c {
  strings:
    $key_9c7c = { cb 0e [2] f9 2c [2] ff 19 [2] d1 19 [2] ee 05 }

  condition:
    any of them
}