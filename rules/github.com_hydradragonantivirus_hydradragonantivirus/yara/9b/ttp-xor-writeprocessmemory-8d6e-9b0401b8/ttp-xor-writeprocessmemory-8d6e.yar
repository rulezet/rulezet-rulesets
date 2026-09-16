rule TTP_XOR_WriteProcessMemory_8d6e {
  strings:
    $key_8d6e = { da 1c [2] e8 3e [2] ee 0b [2] c0 0b [2] ff 17 }

  condition:
    any of them
}