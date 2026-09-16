rule TTP_XOR_WriteProcessMemory_8d60 {
  strings:
    $key_8d60 = { da 12 [2] e8 30 [2] ee 05 [2] c0 05 [2] ff 19 }

  condition:
    any of them
}