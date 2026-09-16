rule TTP_XOR_WriteProcessMemory_9c68 {
  strings:
    $key_9c68 = { cb 1a [2] f9 38 [2] ff 0d [2] d1 0d [2] ee 11 }

  condition:
    any of them
}