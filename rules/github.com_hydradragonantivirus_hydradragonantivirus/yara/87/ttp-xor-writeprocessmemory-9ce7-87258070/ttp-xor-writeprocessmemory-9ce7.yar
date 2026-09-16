rule TTP_XOR_WriteProcessMemory_9ce7 {
  strings:
    $key_9ce7 = { cb 95 [2] f9 b7 [2] ff 82 [2] d1 82 [2] ee 9e }

  condition:
    any of them
}