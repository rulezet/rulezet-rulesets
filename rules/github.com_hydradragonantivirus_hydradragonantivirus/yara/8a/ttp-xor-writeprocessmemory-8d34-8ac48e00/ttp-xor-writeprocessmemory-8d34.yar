rule TTP_XOR_WriteProcessMemory_8d34 {
  strings:
    $key_8d34 = { da 46 [2] e8 64 [2] ee 51 [2] c0 51 [2] ff 4d }

  condition:
    any of them
}