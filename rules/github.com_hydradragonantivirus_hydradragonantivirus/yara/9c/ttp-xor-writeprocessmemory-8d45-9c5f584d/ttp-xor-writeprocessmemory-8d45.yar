rule TTP_XOR_WriteProcessMemory_8d45 {
  strings:
    $key_8d45 = { da 37 [2] e8 15 [2] ee 20 [2] c0 20 [2] ff 3c }

  condition:
    any of them
}