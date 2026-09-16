rule TTP_XOR_WriteProcessMemory_8d10 {
  strings:
    $key_8d10 = { da 62 [2] e8 40 [2] ee 75 [2] c0 75 [2] ff 69 }

  condition:
    any of them
}