rule TTP_XOR_WriteProcessMemory_78c0 {
  strings:
    $key_78c0 = { 2f b2 [2] 1d 90 [2] 1b a5 [2] 35 a5 [2] 0a b9 }

  condition:
    any of them
}