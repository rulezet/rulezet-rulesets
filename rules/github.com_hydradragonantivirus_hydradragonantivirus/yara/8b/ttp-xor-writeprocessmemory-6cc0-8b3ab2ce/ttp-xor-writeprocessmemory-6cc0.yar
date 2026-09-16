rule TTP_XOR_WriteProcessMemory_6cc0 {
  strings:
    $key_6cc0 = { 3b b2 [2] 09 90 [2] 0f a5 [2] 21 a5 [2] 1e b9 }

  condition:
    any of them
}