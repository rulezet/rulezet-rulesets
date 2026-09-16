rule TTP_XOR_WriteProcessMemory_8d2d {
  strings:
    $key_8d2d = { da 5f [2] e8 7d [2] ee 48 [2] c0 48 [2] ff 54 }

  condition:
    any of them
}