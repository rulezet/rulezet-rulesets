rule TTP_XOR_WriteProcessMemory_9c10 {
  strings:
    $key_9c10 = { cb 62 [2] f9 40 [2] ff 75 [2] d1 75 [2] ee 69 }

  condition:
    any of them
}