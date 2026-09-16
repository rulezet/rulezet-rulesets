rule TTP_XOR_WriteProcessMemory_a32f {
  strings:
    $key_a32f = { f4 5d [2] c6 7f [2] c0 4a [2] ee 4a [2] d1 56 }

  condition:
    any of them
}