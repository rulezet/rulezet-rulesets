rule TTP_XOR_WriteProcessMemory_9c3f {
  strings:
    $key_9c3f = { cb 4d [2] f9 6f [2] ff 5a [2] d1 5a [2] ee 46 }

  condition:
    any of them
}