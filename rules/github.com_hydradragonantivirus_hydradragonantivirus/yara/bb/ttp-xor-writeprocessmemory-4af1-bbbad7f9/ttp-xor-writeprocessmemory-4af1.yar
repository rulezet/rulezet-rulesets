rule TTP_XOR_WriteProcessMemory_4af1 {
  strings:
    $key_4af1 = { 1d 83 [2] 2f a1 [2] 29 94 [2] 07 94 [2] 38 88 }

  condition:
    any of them
}