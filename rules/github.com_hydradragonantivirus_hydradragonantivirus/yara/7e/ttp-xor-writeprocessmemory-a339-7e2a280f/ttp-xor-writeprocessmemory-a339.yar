rule TTP_XOR_WriteProcessMemory_a339 {
  strings:
    $key_a339 = { f4 4b [2] c6 69 [2] c0 5c [2] ee 5c [2] d1 40 }

  condition:
    any of them
}