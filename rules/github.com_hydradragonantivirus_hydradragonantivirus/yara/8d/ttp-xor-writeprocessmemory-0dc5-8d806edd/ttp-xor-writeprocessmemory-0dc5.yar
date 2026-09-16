rule TTP_XOR_WriteProcessMemory_0dc5 {
  strings:
    $key_0dc5 = { 5a b7 [2] 68 95 [2] 6e a0 [2] 40 a0 [2] 7f bc }

  condition:
    any of them
}