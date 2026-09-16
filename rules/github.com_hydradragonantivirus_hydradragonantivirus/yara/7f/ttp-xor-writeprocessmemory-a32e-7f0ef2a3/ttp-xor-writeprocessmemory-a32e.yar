rule TTP_XOR_WriteProcessMemory_a32e {
  strings:
    $key_a32e = { f4 5c [2] c6 7e [2] c0 4b [2] ee 4b [2] d1 57 }

  condition:
    any of them
}