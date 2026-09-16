rule TTP_XOR_WriteProcessMemory_29b1 {
  strings:
    $key_29b1 = { 7e c3 [2] 4c e1 [2] 4a d4 [2] 64 d4 [2] 5b c8 }

  condition:
    any of them
}