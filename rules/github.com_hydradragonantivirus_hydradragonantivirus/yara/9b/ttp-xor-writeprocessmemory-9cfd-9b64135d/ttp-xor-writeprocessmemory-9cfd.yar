rule TTP_XOR_WriteProcessMemory_9cfd {
  strings:
    $key_9cfd = { cb 8f [2] f9 ad [2] ff 98 [2] d1 98 [2] ee 84 }

  condition:
    any of them
}