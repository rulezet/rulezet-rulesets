rule TTP_XOR_WriteProcessMemory_9c7f {
  strings:
    $key_9c7f = { cb 0d [2] f9 2f [2] ff 1a [2] d1 1a [2] ee 06 }

  condition:
    any of them
}