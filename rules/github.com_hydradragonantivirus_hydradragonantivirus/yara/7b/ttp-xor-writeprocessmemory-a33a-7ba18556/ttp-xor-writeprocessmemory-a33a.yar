rule TTP_XOR_WriteProcessMemory_a33a {
  strings:
    $key_a33a = { f4 48 [2] c6 6a [2] c0 5f [2] ee 5f [2] d1 43 }

  condition:
    any of them
}