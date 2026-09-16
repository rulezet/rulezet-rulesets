rule TTP_XOR_WriteProcessMemory_8d29 {
  strings:
    $key_8d29 = { da 5b [2] e8 79 [2] ee 4c [2] c0 4c [2] ff 50 }

  condition:
    any of them
}