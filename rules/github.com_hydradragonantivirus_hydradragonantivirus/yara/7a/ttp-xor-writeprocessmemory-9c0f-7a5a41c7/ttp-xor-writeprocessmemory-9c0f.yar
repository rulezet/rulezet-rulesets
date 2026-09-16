rule TTP_XOR_WriteProcessMemory_9c0f {
  strings:
    $key_9c0f = { cb 7d [2] f9 5f [2] ff 6a [2] d1 6a [2] ee 76 }

  condition:
    any of them
}