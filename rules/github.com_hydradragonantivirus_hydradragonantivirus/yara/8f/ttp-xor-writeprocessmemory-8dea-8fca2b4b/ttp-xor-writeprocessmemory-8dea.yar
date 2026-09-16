rule TTP_XOR_WriteProcessMemory_8dea {
  strings:
    $key_8dea = { da 98 [2] e8 ba [2] ee 8f [2] c0 8f [2] ff 93 }

  condition:
    any of them
}