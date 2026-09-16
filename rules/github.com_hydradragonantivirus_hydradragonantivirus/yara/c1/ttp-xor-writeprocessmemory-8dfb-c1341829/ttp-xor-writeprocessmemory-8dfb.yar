rule TTP_XOR_WriteProcessMemory_8dfb {
  strings:
    $key_8dfb = { da 89 [2] e8 ab [2] ee 9e [2] c0 9e [2] ff 82 }

  condition:
    any of them
}