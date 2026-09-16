rule TTP_XOR_WriteProcessMemory_8d01 {
  strings:
    $key_8d01 = { da 73 [2] e8 51 [2] ee 64 [2] c0 64 [2] ff 78 }

  condition:
    any of them
}