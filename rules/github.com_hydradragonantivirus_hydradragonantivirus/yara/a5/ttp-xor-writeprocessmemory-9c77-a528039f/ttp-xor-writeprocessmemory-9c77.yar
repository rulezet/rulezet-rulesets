rule TTP_XOR_WriteProcessMemory_9c77 {
  strings:
    $key_9c77 = { cb 05 [2] f9 27 [2] ff 12 [2] d1 12 [2] ee 0e }

  condition:
    any of them
}