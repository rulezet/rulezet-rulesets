rule TTP_XOR_WriteProcessMemory_9c4a {
  strings:
    $key_9c4a = { cb 38 [2] f9 1a [2] ff 2f [2] d1 2f [2] ee 33 }

  condition:
    any of them
}