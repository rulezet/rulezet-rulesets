rule TTP_XOR_WriteProcessMemory_8d8c {
  strings:
    $key_8d8c = { da fe [2] e8 dc [2] ee e9 [2] c0 e9 [2] ff f5 }

  condition:
    any of them
}