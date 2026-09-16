rule TTP_XOR_WriteProcessMemory_9cf2 {
  strings:
    $key_9cf2 = { cb 80 [2] f9 a2 [2] ff 97 [2] d1 97 [2] ee 8b }

  condition:
    any of them
}