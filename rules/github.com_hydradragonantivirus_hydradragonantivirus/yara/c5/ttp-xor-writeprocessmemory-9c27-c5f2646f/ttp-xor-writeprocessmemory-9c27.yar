rule TTP_XOR_WriteProcessMemory_9c27 {
  strings:
    $key_9c27 = { cb 55 [2] f9 77 [2] ff 42 [2] d1 42 [2] ee 5e }

  condition:
    any of them
}