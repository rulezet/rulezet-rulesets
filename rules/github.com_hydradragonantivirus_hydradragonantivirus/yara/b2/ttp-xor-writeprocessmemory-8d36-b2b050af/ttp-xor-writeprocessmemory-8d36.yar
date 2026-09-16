rule TTP_XOR_WriteProcessMemory_8d36 {
  strings:
    $key_8d36 = { da 44 [2] e8 66 [2] ee 53 [2] c0 53 [2] ff 4f }

  condition:
    any of them
}