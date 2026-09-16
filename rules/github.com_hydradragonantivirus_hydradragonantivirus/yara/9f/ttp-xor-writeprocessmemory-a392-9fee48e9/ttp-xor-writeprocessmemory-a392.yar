rule TTP_XOR_WriteProcessMemory_a392 {
  strings:
    $key_a392 = { f4 e0 [2] c6 c2 [2] c0 f7 [2] ee f7 [2] d1 eb }

  condition:
    any of them
}