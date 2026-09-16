rule TTP_XOR_WriteProcessMemory_9c67 {
  strings:
    $key_9c67 = { cb 15 [2] f9 37 [2] ff 02 [2] d1 02 [2] ee 1e }

  condition:
    any of them
}