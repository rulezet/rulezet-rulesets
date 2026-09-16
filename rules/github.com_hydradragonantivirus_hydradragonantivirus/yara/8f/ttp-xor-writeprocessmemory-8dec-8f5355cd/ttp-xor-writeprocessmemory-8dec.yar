rule TTP_XOR_WriteProcessMemory_8dec {
  strings:
    $key_8dec = { da 9e [2] e8 bc [2] ee 89 [2] c0 89 [2] ff 95 }

  condition:
    any of them
}