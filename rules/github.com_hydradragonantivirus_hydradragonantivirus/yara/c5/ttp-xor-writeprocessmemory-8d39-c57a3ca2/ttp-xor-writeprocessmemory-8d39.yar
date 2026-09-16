rule TTP_XOR_WriteProcessMemory_8d39 {
  strings:
    $key_8d39 = { da 4b [2] e8 69 [2] ee 5c [2] c0 5c [2] ff 40 }

  condition:
    any of them
}