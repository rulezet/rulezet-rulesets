rule TTP_XOR_WriteProcessMemory_9c2d {
  strings:
    $key_9c2d = { cb 5f [2] f9 7d [2] ff 48 [2] d1 48 [2] ee 54 }

  condition:
    any of them
}