rule TTP_XOR_WriteProcessMemory_9c07 {
  strings:
    $key_9c07 = { cb 75 [2] f9 57 [2] ff 62 [2] d1 62 [2] ee 7e }

  condition:
    any of them
}