rule TTP_XOR_WriteProcessMemory_9c6a {
  strings:
    $key_9c6a = { cb 18 [2] f9 3a [2] ff 0f [2] d1 0f [2] ee 13 }

  condition:
    any of them
}