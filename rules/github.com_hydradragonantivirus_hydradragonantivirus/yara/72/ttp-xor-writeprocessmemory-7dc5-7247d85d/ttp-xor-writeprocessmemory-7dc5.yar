rule TTP_XOR_WriteProcessMemory_7dc5 {
  strings:
    $key_7dc5 = { 2a b7 [2] 18 95 [2] 1e a0 [2] 30 a0 [2] 0f bc }

  condition:
    any of them
}