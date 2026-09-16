rule TTP_XOR_WriteProcessMemory_9c73 {
  strings:
    $key_9c73 = { cb 01 [2] f9 23 [2] ff 16 [2] d1 16 [2] ee 0a }

  condition:
    any of them
}