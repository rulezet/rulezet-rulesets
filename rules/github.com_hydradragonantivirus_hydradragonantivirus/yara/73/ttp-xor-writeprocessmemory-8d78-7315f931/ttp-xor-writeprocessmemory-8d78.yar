rule TTP_XOR_WriteProcessMemory_8d78 {
  strings:
    $key_8d78 = { da 0a [2] e8 28 [2] ee 1d [2] c0 1d [2] ff 01 }

  condition:
    any of them
}