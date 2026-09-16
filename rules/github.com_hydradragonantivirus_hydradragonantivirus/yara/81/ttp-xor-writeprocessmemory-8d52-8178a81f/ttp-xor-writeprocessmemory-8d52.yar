rule TTP_XOR_WriteProcessMemory_8d52 {
  strings:
    $key_8d52 = { da 20 [2] e8 02 [2] ee 37 [2] c0 37 [2] ff 2b }

  condition:
    any of them
}