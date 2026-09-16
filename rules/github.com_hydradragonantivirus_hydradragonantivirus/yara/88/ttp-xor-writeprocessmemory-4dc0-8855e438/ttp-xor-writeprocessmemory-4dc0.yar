rule TTP_XOR_WriteProcessMemory_4dc0 {
  strings:
    $key_4dc0 = { 1a b2 [2] 28 90 [2] 2e a5 [2] 00 a5 [2] 3f b9 }

  condition:
    any of them
}