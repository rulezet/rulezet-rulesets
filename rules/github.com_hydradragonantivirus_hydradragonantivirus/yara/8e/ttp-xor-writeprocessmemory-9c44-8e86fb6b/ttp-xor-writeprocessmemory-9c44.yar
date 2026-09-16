rule TTP_XOR_WriteProcessMemory_9c44 {
  strings:
    $key_9c44 = { cb 36 [2] f9 14 [2] ff 21 [2] d1 21 [2] ee 3d }

  condition:
    any of them
}