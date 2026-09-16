rule TTP_XOR_WriteProcessMemory_a32d {
  strings:
    $key_a32d = { f4 5f [2] c6 7d [2] c0 48 [2] ee 48 [2] d1 54 }

  condition:
    any of them
}