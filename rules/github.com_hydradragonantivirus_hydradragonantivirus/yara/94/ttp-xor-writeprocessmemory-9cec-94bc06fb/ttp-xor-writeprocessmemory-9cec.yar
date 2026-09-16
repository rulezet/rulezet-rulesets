rule TTP_XOR_WriteProcessMemory_9cec {
  strings:
    $key_9cec = { cb 9e [2] f9 bc [2] ff 89 [2] d1 89 [2] ee 95 }

  condition:
    any of them
}