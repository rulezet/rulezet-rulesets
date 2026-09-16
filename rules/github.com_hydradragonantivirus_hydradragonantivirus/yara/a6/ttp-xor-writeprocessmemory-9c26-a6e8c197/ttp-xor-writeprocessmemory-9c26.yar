rule TTP_XOR_WriteProcessMemory_9c26 {
  strings:
    $key_9c26 = { cb 54 [2] f9 76 [2] ff 43 [2] d1 43 [2] ee 5f }

  condition:
    any of them
}