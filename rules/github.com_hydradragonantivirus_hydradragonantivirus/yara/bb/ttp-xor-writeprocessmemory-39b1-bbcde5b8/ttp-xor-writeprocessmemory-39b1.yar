rule TTP_XOR_WriteProcessMemory_39b1 {
  strings:
    $key_39b1 = { 6e c3 [2] 5c e1 [2] 5a d4 [2] 74 d4 [2] 4b c8 }

  condition:
    any of them
}