rule TTP_XOR_WriteProcessMemory_8d18 {
  strings:
    $key_8d18 = { da 6a [2] e8 48 [2] ee 7d [2] c0 7d [2] ff 61 }

  condition:
    any of them
}