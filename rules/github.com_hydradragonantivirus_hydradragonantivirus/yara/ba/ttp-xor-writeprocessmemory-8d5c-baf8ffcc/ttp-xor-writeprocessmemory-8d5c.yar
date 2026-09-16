rule TTP_XOR_WriteProcessMemory_8d5c {
  strings:
    $key_8d5c = { da 2e [2] e8 0c [2] ee 39 [2] c0 39 [2] ff 25 }

  condition:
    any of them
}