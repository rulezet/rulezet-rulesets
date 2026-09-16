rule TTP_XOR_WriteProcessMemory_8de1 {
  strings:
    $key_8de1 = { da 93 [2] e8 b1 [2] ee 84 [2] c0 84 [2] ff 98 }

  condition:
    any of them
}