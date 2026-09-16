rule TTP_XOR_WriteProcessMemory_a31d {
  strings:
    $key_a31d = { f4 6f [2] c6 4d [2] c0 78 [2] ee 78 [2] d1 64 }

  condition:
    any of them
}