rule TTP_XOR_WriteProcessMemory_8d31 {
  strings:
    $key_8d31 = { da 43 [2] e8 61 [2] ee 54 [2] c0 54 [2] ff 48 }

  condition:
    any of them
}