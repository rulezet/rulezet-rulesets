rule TTP_XOR_WriteProcessMemory_9c53 {
  strings:
    $key_9c53 = { cb 21 [2] f9 03 [2] ff 36 [2] d1 36 [2] ee 2a }

  condition:
    any of them
}