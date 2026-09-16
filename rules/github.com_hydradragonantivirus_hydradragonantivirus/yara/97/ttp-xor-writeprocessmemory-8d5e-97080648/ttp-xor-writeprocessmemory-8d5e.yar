rule TTP_XOR_WriteProcessMemory_8d5e {
  strings:
    $key_8d5e = { da 2c [2] e8 0e [2] ee 3b [2] c0 3b [2] ff 27 }

  condition:
    any of them
}