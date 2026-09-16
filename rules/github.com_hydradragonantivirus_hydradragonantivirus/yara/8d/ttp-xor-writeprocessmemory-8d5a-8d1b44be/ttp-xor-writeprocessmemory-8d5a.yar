rule TTP_XOR_WriteProcessMemory_8d5a {
  strings:
    $key_8d5a = { da 28 [2] e8 0a [2] ee 3f [2] c0 3f [2] ff 23 }

  condition:
    any of them
}