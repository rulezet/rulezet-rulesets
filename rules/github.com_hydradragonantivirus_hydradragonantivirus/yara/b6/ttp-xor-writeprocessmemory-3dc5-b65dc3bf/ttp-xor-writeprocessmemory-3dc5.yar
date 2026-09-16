rule TTP_XOR_WriteProcessMemory_3dc5 {
  strings:
    $key_3dc5 = { 6a b7 [2] 58 95 [2] 5e a0 [2] 70 a0 [2] 4f bc }

  condition:
    any of them
}