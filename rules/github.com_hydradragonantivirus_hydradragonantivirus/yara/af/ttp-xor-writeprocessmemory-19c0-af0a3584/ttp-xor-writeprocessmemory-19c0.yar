rule TTP_XOR_WriteProcessMemory_19c0 {
  strings:
    $key_19c0 = { 4e b2 [2] 7c 90 [2] 7a a5 [2] 54 a5 [2] 6b b9 }

  condition:
    any of them
}