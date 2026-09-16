rule TTP_XOR_WriteProcessMemory_9cef {
  strings:
    $key_9cef = { cb 9d [2] f9 bf [2] ff 8a [2] d1 8a [2] ee 96 }

  condition:
    any of them
}