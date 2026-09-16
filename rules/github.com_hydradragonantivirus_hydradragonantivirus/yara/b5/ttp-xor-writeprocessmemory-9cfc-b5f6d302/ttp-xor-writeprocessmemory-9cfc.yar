rule TTP_XOR_WriteProcessMemory_9cfc {
  strings:
    $key_9cfc = { cb 8e [2] f9 ac [2] ff 99 [2] d1 99 [2] ee 85 }

  condition:
    any of them
}