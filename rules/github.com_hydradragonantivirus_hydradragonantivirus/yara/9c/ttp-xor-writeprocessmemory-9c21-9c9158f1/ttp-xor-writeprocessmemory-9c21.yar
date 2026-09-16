rule TTP_XOR_WriteProcessMemory_9c21 {
  strings:
    $key_9c21 = { cb 53 [2] f9 71 [2] ff 44 [2] d1 44 [2] ee 58 }

  condition:
    any of them
}