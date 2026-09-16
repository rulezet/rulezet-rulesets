rule TTP_XOR_WriteProcessMemory_8dfc {
  strings:
    $key_8dfc = { da 8e [2] e8 ac [2] ee 99 [2] c0 99 [2] ff 85 }

  condition:
    any of them
}