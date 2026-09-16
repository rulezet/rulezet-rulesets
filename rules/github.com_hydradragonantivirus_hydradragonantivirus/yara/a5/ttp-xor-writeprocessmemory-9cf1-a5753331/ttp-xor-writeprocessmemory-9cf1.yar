rule TTP_XOR_WriteProcessMemory_9cf1 {
  strings:
    $key_9cf1 = { cb 83 [2] f9 a1 [2] ff 94 [2] d1 94 [2] ee 88 }

  condition:
    any of them
}