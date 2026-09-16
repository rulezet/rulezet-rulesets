rule TTP_XOR_WriteProcessMemory_8df9 {
  strings:
    $key_8df9 = { da 8b [2] e8 a9 [2] ee 9c [2] c0 9c [2] ff 80 }

  condition:
    any of them
}