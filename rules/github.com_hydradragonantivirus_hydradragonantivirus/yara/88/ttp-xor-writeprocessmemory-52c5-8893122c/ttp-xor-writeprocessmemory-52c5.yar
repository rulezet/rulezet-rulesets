rule TTP_XOR_WriteProcessMemory_52c5 {
  strings:
    $key_52c5 = { 05 b7 [2] 37 95 [2] 31 a0 [2] 1f a0 [2] 20 bc }

  condition:
    any of them
}