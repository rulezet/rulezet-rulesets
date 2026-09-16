rule TTP_XOR_WriteProcessMemory_8dd9 {
  strings:
    $key_8dd9 = { da ab [2] e8 89 [2] ee bc [2] c0 bc [2] ff a0 }

  condition:
    any of them
}