rule TTP_XOR_WriteProcessMemory_39b0 {
  strings:
    $key_39b0 = { 6e c2 [2] 5c e0 [2] 5a d5 [2] 74 d5 [2] 4b c9 }

  condition:
    any of them
}