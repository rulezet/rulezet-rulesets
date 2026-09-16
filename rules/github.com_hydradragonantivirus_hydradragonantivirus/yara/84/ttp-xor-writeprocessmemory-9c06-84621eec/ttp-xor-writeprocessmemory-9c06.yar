rule TTP_XOR_WriteProcessMemory_9c06 {
  strings:
    $key_9c06 = { cb 74 [2] f9 56 [2] ff 63 [2] d1 63 [2] ee 7f }

  condition:
    any of them
}