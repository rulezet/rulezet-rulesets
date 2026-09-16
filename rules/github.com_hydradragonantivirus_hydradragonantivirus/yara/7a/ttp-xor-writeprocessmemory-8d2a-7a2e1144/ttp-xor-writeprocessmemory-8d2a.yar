rule TTP_XOR_WriteProcessMemory_8d2a {
  strings:
    $key_8d2a = { da 58 [2] e8 7a [2] ee 4f [2] c0 4f [2] ff 53 }

  condition:
    any of them
}