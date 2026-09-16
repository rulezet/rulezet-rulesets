rule TTP_XOR_WriteProcessMemory_a3ec {
  strings:
    $key_a3ec = { f4 9e [2] c6 bc [2] c0 89 [2] ee 89 [2] d1 95 }

  condition:
    any of them
}