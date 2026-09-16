rule TTP_XOR_WriteProcessMemory_8d76 {
  strings:
    $key_8d76 = { da 04 [2] e8 26 [2] ee 13 [2] c0 13 [2] ff 0f }

  condition:
    any of them
}