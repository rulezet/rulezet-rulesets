rule TTP_XOR_WriteProcessMemory_8d19 {
  strings:
    $key_8d19 = { da 6b [2] e8 49 [2] ee 7c [2] c0 7c [2] ff 60 }

  condition:
    any of them
}