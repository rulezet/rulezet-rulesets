rule TTP_XOR_WriteProcessMemory_8d41 {
  strings:
    $key_8d41 = { da 33 [2] e8 11 [2] ee 24 [2] c0 24 [2] ff 38 }

  condition:
    any of them
}