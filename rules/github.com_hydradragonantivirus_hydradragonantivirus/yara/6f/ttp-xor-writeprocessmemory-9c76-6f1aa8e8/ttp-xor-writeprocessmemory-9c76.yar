rule TTP_XOR_WriteProcessMemory_9c76 {
  strings:
    $key_9c76 = { cb 04 [2] f9 26 [2] ff 13 [2] d1 13 [2] ee 0f }

  condition:
    any of them
}