rule TTP_XOR_WriteProcessMemory_a31f {
  strings:
    $key_a31f = { f4 6d [2] c6 4f [2] c0 7a [2] ee 7a [2] d1 66 }

  condition:
    any of them
}