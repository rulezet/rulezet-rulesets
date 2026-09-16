rule TTP_XOR_WriteProcessMemory_8d26 {
  strings:
    $key_8d26 = { da 54 [2] e8 76 [2] ee 43 [2] c0 43 [2] ff 5f }

  condition:
    any of them
}