rule TTP_XOR_WriteProcessMemory_29f0 {
  strings:
    $key_29f0 = { 7e 82 [2] 4c a0 [2] 4a 95 [2] 64 95 [2] 5b 89 }

  condition:
    any of them
}