rule TTP_XOR_WriteProcessMemory_9c1d {
  strings:
    $key_9c1d = { cb 6f [2] f9 4d [2] ff 78 [2] d1 78 [2] ee 64 }

  condition:
    any of them
}