rule TTP_XOR_WriteProcessMemory_8d71 {
  strings:
    $key_8d71 = { da 03 [2] e8 21 [2] ee 14 [2] c0 14 [2] ff 08 }

  condition:
    any of them
}