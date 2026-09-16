rule TTP_XOR_WriteProcessMemory_a3fa {
  strings:
    $key_a3fa = { f4 88 [2] c6 aa [2] c0 9f [2] ee 9f [2] d1 83 }

  condition:
    any of them
}