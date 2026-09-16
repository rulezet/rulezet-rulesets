rule TTP_XOR_WriteProcessMemory_39f0 {
  strings:
    $key_39f0 = { 6e 82 [2] 5c a0 [2] 5a 95 [2] 74 95 [2] 4b 89 }

  condition:
    any of them
}