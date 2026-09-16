rule TTP_XOR_WriteProcessMemory_a31a {
  strings:
    $key_a31a = { f4 68 [2] c6 4a [2] c0 7f [2] ee 7f [2] d1 63 }

  condition:
    any of them
}