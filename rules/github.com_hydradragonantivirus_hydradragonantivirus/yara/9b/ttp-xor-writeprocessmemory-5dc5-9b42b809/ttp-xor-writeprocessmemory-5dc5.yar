rule TTP_XOR_WriteProcessMemory_5dc5 {
  strings:
    $key_5dc5 = { 0a b7 [2] 38 95 [2] 3e a0 [2] 10 a0 [2] 2f bc }

  condition:
    any of them
}