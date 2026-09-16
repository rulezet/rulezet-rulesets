rule TTP_XOR_WriteProcessMemory_9ce9 {
  strings:
    $key_9ce9 = { cb 9b [2] f9 b9 [2] ff 8c [2] d1 8c [2] ee 90 }

  condition:
    any of them
}