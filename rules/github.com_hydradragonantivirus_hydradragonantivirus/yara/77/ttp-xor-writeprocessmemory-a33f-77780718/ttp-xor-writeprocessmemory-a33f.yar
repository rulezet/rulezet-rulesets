rule TTP_XOR_WriteProcessMemory_a33f {
  strings:
    $key_a33f = { f4 4d [2] c6 6f [2] c0 5a [2] ee 5a [2] d1 46 }

  condition:
    any of them
}