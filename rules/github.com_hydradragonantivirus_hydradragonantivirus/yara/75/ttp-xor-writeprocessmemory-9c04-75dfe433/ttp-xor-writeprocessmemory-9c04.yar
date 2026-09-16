rule TTP_XOR_WriteProcessMemory_9c04 {
  strings:
    $key_9c04 = { cb 76 [2] f9 54 [2] ff 61 [2] d1 61 [2] ee 7d }

  condition:
    any of them
}