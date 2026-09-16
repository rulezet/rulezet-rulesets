rule TTP_XOR_WriteProcessMemory_8d48 {
  strings:
    $key_8d48 = { da 3a [2] e8 18 [2] ee 2d [2] c0 2d [2] ff 31 }

  condition:
    any of them
}