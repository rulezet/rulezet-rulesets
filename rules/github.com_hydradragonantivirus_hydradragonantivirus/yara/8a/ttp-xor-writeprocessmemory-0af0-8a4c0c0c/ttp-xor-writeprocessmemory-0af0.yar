rule TTP_XOR_WriteProcessMemory_0af0 {
  strings:
    $key_0af0 = { 5d 82 [2] 6f a0 [2] 69 95 [2] 47 95 [2] 78 89 }

  condition:
    any of them
}