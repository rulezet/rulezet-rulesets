rule TTP_XOR_WriteProcessMemory_b2c0 {
  strings:
    $key_b2c0 = { e5 b2 [2] d7 90 [2] d1 a5 [2] ff a5 [2] c0 b9 }

  condition:
    any of them
}