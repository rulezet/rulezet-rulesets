rule TTP_XOR_WriteProcessMemory_9c5a {
  strings:
    $key_9c5a = { cb 28 [2] f9 0a [2] ff 3f [2] d1 3f [2] ee 23 }

  condition:
    any of them
}