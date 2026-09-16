rule TTP_XOR_WriteProcessMemory_48c0 {
  strings:
    $key_48c0 = { 1f b2 [2] 2d 90 [2] 2b a5 [2] 05 a5 [2] 3a b9 }

  condition:
    any of them
}