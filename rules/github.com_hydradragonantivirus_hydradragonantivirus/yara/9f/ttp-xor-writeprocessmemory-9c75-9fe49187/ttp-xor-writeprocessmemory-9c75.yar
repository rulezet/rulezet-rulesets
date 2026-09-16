rule TTP_XOR_WriteProcessMemory_9c75 {
  strings:
    $key_9c75 = { cb 07 [2] f9 25 [2] ff 10 [2] d1 10 [2] ee 0c }

  condition:
    any of them
}