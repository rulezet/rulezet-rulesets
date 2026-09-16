rule TTP_XOR_WriteProcessMemory_6cc1 {
  strings:
    $key_6cc1 = { 3b b3 [2] 09 91 [2] 0f a4 [2] 21 a4 [2] 1e b8 }

  condition:
    any of them
}