rule TTP_XOR_WriteProcessMemory_9c39 {
  strings:
    $key_9c39 = { cb 4b [2] f9 69 [2] ff 5c [2] d1 5c [2] ee 40 }

  condition:
    any of them
}