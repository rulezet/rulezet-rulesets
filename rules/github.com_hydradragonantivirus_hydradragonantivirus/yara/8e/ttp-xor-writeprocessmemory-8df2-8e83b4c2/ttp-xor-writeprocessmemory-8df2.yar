rule TTP_XOR_WriteProcessMemory_8df2 {
  strings:
    $key_8df2 = { da 80 [2] e8 a2 [2] ee 97 [2] c0 97 [2] ff 8b }

  condition:
    any of them
}