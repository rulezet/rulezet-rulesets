rule TTP_XOR_WriteProcessMemory_8d7e {
  strings:
    $key_8d7e = { da 0c [2] e8 2e [2] ee 1b [2] c0 1b [2] ff 07 }

  condition:
    any of them
}