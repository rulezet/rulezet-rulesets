rule TTP_XOR_WriteProcessMemory_9c71 {
  strings:
    $key_9c71 = { cb 03 [2] f9 21 [2] ff 14 [2] d1 14 [2] ee 08 }

  condition:
    any of them
}