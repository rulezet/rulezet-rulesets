rule TTP_XOR_WriteProcessMemory_8d44 {
  strings:
    $key_8d44 = { da 36 [2] e8 14 [2] ee 21 [2] c0 21 [2] ff 3d }

  condition:
    any of them
}