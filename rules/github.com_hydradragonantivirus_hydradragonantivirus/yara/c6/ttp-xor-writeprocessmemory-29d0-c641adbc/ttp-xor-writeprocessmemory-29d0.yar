rule TTP_XOR_WriteProcessMemory_29d0 {
  strings:
    $key_29d0 = { 7e a2 [2] 4c 80 [2] 4a b5 [2] 64 b5 [2] 5b a9 }

  condition:
    any of them
}