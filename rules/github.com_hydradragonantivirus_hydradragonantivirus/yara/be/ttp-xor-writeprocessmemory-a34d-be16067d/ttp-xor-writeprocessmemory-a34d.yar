rule TTP_XOR_WriteProcessMemory_a34d {
  strings:
    $key_a34d = { f4 3f [2] c6 1d [2] c0 28 [2] ee 28 [2] d1 34 }

  condition:
    any of them
}