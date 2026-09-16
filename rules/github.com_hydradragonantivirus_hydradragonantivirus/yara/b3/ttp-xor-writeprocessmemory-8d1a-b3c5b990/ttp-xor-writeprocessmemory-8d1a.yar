rule TTP_XOR_WriteProcessMemory_8d1a {
  strings:
    $key_8d1a = { da 68 [2] e8 4a [2] ee 7f [2] c0 7f [2] ff 63 }

  condition:
    any of them
}