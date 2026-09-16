rule TTP_XOR_WriteProcessMemory_a30c {
  strings:
    $key_a30c = { f4 7e [2] c6 5c [2] c0 69 [2] ee 69 [2] d1 75 }

  condition:
    any of them
}