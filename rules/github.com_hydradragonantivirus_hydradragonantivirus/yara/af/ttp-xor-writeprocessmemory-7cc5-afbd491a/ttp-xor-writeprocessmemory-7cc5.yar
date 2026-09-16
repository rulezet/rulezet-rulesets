rule TTP_XOR_WriteProcessMemory_7cc5 {
  strings:
    $key_7cc5 = { 2b b7 [2] 19 95 [2] 1f a0 [2] 31 a0 [2] 0e bc }

  condition:
    any of them
}