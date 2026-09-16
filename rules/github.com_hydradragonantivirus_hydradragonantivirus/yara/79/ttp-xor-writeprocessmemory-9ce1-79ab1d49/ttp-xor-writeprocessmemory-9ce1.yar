rule TTP_XOR_WriteProcessMemory_9ce1 {
  strings:
    $key_9ce1 = { cb 93 [2] f9 b1 [2] ff 84 [2] d1 84 [2] ee 98 }

  condition:
    any of them
}