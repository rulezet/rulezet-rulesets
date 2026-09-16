rule TTP_XOR_WriteProcessMemory_19f0 {
  strings:
    $key_19f0 = { 4e 82 [2] 7c a0 [2] 7a 95 [2] 54 95 [2] 6b 89 }

  condition:
    any of them
}