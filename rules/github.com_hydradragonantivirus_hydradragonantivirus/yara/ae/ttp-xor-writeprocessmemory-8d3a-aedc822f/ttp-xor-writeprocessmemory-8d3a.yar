rule TTP_XOR_WriteProcessMemory_8d3a {
  strings:
    $key_8d3a = { da 48 [2] e8 6a [2] ee 5f [2] c0 5f [2] ff 43 }

  condition:
    any of them
}