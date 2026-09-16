rule TTP_XOR_WriteProcessMemory_9c1a {
  strings:
    $key_9c1a = { cb 68 [2] f9 4a [2] ff 7f [2] d1 7f [2] ee 63 }

  condition:
    any of them
}