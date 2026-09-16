rule TTP_XOR_WriteProcessMemory_eda0 {
  strings:
    $key_eda0 = { ba d2 [2] 88 f0 [2] 8e c5 [2] a0 c5 [2] 9f d9 }

  condition:
    any of them
}