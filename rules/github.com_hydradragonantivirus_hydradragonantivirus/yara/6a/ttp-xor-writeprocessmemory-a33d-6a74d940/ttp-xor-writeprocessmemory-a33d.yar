rule TTP_XOR_WriteProcessMemory_a33d {
  strings:
    $key_a33d = { f4 4f [2] c6 6d [2] c0 58 [2] ee 58 [2] d1 44 }

  condition:
    any of them
}