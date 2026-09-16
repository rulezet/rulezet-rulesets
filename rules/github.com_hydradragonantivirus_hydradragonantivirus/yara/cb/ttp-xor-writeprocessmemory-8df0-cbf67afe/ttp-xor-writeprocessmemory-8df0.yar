rule TTP_XOR_WriteProcessMemory_8df0 {
  strings:
    $key_8df0 = { da 82 [2] e8 a0 [2] ee 95 [2] c0 95 [2] ff 89 }

  condition:
    any of them
}