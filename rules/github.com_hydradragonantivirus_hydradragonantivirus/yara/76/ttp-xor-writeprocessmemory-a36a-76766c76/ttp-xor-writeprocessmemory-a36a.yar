rule TTP_XOR_WriteProcessMemory_a36a {
  strings:
    $key_a36a = { f4 18 [2] c6 3a [2] c0 0f [2] ee 0f [2] d1 13 }

  condition:
    any of them
}