rule TTP_XOR_WriteProcessMemory_8da9 {
  strings:
    $key_8da9 = { da db [2] e8 f9 [2] ee cc [2] c0 cc [2] ff d0 }

  condition:
    any of them
}