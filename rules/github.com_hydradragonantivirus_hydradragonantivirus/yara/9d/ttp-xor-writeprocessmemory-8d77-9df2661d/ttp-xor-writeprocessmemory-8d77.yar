rule TTP_XOR_WriteProcessMemory_8d77 {
  strings:
    $key_8d77 = { da 05 [2] e8 27 [2] ee 12 [2] c0 12 [2] ff 0e }

  condition:
    any of them
}