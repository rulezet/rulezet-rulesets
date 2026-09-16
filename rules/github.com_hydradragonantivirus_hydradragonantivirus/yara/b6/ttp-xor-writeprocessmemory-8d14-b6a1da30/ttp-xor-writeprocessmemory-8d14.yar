rule TTP_XOR_WriteProcessMemory_8d14 {
  strings:
    $key_8d14 = { da 66 [2] e8 44 [2] ee 71 [2] c0 71 [2] ff 6d }

  condition:
    any of them
}