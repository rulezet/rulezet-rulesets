rule TTP_XOR_WriteProcessMemory_0fe1 {
  strings:
    $key_0fe1 = { 58 93 [2] 6a b1 [2] 6c 84 [2] 42 84 [2] 7d 98 }

  condition:
    any of them
}