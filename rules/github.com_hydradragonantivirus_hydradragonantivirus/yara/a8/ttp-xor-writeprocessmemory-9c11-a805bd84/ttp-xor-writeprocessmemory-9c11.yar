rule TTP_XOR_WriteProcessMemory_9c11 {
  strings:
    $key_9c11 = { cb 63 [2] f9 41 [2] ff 74 [2] d1 74 [2] ee 68 }

  condition:
    any of them
}