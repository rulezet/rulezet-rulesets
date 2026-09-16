rule TTP_XOR_WriteProcessMemory_8d2c {
  strings:
    $key_8d2c = { da 5e [2] e8 7c [2] ee 49 [2] c0 49 [2] ff 55 }

  condition:
    any of them
}