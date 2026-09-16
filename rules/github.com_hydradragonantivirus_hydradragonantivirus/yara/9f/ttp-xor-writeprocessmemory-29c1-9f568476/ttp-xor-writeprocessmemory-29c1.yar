rule TTP_XOR_WriteProcessMemory_29c1 {
  strings:
    $key_29c1 = { 7e b3 [2] 4c 91 [2] 4a a4 [2] 64 a4 [2] 5b b8 }

  condition:
    any of them
}