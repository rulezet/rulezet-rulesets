rule TTP_XOR_WriteProcessMemory_9ceb {
  strings:
    $key_9ceb = { cb 99 [2] f9 bb [2] ff 8e [2] d1 8e [2] ee 92 }

  condition:
    any of them
}