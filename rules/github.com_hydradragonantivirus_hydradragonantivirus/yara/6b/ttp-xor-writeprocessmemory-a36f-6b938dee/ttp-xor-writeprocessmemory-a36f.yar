rule TTP_XOR_WriteProcessMemory_a36f {
  strings:
    $key_a36f = { f4 1d [2] c6 3f [2] c0 0a [2] ee 0a [2] d1 16 }

  condition:
    any of them
}