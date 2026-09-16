rule TTP_XOR_WriteProcessMemory_9c0d {
  strings:
    $key_9c0d = { cb 7f [2] f9 5d [2] ff 68 [2] d1 68 [2] ee 74 }

  condition:
    any of them
}