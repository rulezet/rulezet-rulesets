rule TTP_XOR_WriteProcessMemory_9c5d {
  strings:
    $key_9c5d = { cb 2f [2] f9 0d [2] ff 38 [2] d1 38 [2] ee 24 }

  condition:
    any of them
}