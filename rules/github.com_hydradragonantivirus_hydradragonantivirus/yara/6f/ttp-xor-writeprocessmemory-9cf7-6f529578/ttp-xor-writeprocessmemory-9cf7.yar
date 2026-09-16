rule TTP_XOR_WriteProcessMemory_9cf7 {
  strings:
    $key_9cf7 = { cb 85 [2] f9 a7 [2] ff 92 [2] d1 92 [2] ee 8e }

  condition:
    any of them
}