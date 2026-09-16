rule TTP_XOR_WriteProcessMemory_8de9 {
  strings:
    $key_8de9 = { da 9b [2] e8 b9 [2] ee 8c [2] c0 8c [2] ff 90 }

  condition:
    any of them
}