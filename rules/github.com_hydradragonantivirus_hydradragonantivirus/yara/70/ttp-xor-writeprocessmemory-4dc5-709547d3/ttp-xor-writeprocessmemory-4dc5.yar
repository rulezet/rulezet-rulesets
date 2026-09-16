rule TTP_XOR_WriteProcessMemory_4dc5 {
  strings:
    $key_4dc5 = { 1a b7 [2] 28 95 [2] 2e a0 [2] 00 a0 [2] 3f bc }

  condition:
    any of them
}