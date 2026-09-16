rule TTP_XOR_WriteProcessMemory_9c52 {
  strings:
    $key_9c52 = { cb 20 [2] f9 02 [2] ff 37 [2] d1 37 [2] ee 2b }

  condition:
    any of them
}