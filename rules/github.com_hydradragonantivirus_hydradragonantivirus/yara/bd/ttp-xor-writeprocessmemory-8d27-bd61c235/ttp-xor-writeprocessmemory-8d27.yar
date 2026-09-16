rule TTP_XOR_WriteProcessMemory_8d27 {
  strings:
    $key_8d27 = { da 55 [2] e8 77 [2] ee 42 [2] c0 42 [2] ff 5e }

  condition:
    any of them
}