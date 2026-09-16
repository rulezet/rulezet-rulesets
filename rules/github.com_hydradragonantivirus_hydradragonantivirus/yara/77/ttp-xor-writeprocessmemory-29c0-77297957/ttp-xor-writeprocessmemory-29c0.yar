rule TTP_XOR_WriteProcessMemory_29c0 {
  strings:
    $key_29c0 = { 7e b2 [2] 4c 90 [2] 4a a5 [2] 64 a5 [2] 5b b9 }

  condition:
    any of them
}