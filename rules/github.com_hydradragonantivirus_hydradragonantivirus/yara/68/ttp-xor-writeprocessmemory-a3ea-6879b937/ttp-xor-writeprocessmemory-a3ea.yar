rule TTP_XOR_WriteProcessMemory_a3ea {
  strings:
    $key_a3ea = { f4 98 [2] c6 ba [2] c0 8f [2] ee 8f [2] d1 93 }

  condition:
    any of them
}