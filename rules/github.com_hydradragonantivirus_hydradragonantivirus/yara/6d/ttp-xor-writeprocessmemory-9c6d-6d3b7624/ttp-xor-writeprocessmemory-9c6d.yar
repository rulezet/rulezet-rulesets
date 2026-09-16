rule TTP_XOR_WriteProcessMemory_9c6d {
  strings:
    $key_9c6d = { cb 1f [2] f9 3d [2] ff 08 [2] d1 08 [2] ee 14 }

  condition:
    any of them
}