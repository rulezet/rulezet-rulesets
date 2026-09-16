rule TTP_XOR_WriteProcessMemory_9c20 {
  strings:
    $key_9c20 = { cb 52 [2] f9 70 [2] ff 45 [2] d1 45 [2] ee 59 }

  condition:
    any of them
}