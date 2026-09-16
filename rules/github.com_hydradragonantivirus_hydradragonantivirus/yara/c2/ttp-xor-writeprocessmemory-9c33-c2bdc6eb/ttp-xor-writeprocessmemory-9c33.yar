rule TTP_XOR_WriteProcessMemory_9c33 {
  strings:
    $key_9c33 = { cb 41 [2] f9 63 [2] ff 56 [2] d1 56 [2] ee 4a }

  condition:
    any of them
}