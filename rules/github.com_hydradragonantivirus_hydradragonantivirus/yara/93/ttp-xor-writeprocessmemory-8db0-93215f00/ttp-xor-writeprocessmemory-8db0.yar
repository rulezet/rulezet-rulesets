rule TTP_XOR_WriteProcessMemory_8db0 {
  strings:
    $key_8db0 = { da c2 [2] e8 e0 [2] ee d5 [2] c0 d5 [2] ff c9 }

  condition:
    any of them
}