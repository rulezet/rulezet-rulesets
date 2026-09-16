rule TTP_XOR_WriteProcessMemory_9c51 {
  strings:
    $key_9c51 = { cb 23 [2] f9 01 [2] ff 34 [2] d1 34 [2] ee 28 }

  condition:
    any of them
}