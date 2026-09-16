rule TTP_XOR_WriteProcessMemory_8d8b {
  strings:
    $key_8d8b = { da f9 [2] e8 db [2] ee ee [2] c0 ee [2] ff f2 }

  condition:
    any of them
}