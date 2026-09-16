rule TTP_XOR_WriteProcessMemory_a34a {
  strings:
    $key_a34a = { f4 38 [2] c6 1a [2] c0 2f [2] ee 2f [2] d1 33 }

  condition:
    any of them
}