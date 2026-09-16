rule TTP_XOR_WriteProcessMemory_9c40 {
  strings:
    $key_9c40 = { cb 32 [2] f9 10 [2] ff 25 [2] d1 25 [2] ee 39 }

  condition:
    any of them
}