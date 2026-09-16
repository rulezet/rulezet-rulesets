rule TTP_XOR_WriteProcessMemory_9ced {
  strings:
    $key_9ced = { cb 9f [2] f9 bd [2] ff 88 [2] d1 88 [2] ee 94 }

  condition:
    any of them
}