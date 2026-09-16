rule TTP_XOR_WriteProcessMemory_9c72 {
  strings:
    $key_9c72 = { cb 00 [2] f9 22 [2] ff 17 [2] d1 17 [2] ee 0b }

  condition:
    any of them
}