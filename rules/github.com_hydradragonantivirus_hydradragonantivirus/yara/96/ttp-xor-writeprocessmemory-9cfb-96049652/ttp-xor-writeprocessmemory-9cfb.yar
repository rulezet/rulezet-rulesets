rule TTP_XOR_WriteProcessMemory_9cfb {
  strings:
    $key_9cfb = { cb 89 [2] f9 ab [2] ff 9e [2] d1 9e [2] ee 82 }

  condition:
    any of them
}