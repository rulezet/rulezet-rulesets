rule TTP_XOR_WriteProcessMemory_9c08 {
  strings:
    $key_9c08 = { cb 7a [2] f9 58 [2] ff 6d [2] d1 6d [2] ee 71 }

  condition:
    any of them
}