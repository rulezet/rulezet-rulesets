rule TTP_XOR_WriteProcessMemory_9c35 {
  strings:
    $key_9c35 = { cb 47 [2] f9 65 [2] ff 50 [2] d1 50 [2] ee 4c }

  condition:
    any of them
}