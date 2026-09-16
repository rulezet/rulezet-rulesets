rule TTP_XOR_WriteProcessMemory_a329 {
  strings:
    $key_a329 = { f4 5b [2] c6 79 [2] c0 4c [2] ee 4c [2] d1 50 }

  condition:
    any of them
}