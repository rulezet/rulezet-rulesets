rule TTP_XOR_WriteProcessMemory_8ded {
  strings:
    $key_8ded = { da 9f [2] e8 bd [2] ee 88 [2] c0 88 [2] ff 94 }

  condition:
    any of them
}