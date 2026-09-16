rule TTP_XOR_WriteProcessMemory_9c61 {
  strings:
    $key_9c61 = { cb 13 [2] f9 31 [2] ff 04 [2] d1 04 [2] ee 18 }

  condition:
    any of them
}