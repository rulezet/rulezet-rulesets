rule TTP_XOR_WriteProcessMemory_29b2 {
  strings:
    $key_29b2 = { 7e c0 [2] 4c e2 [2] 4a d7 [2] 64 d7 [2] 5b cb }

  condition:
    any of them
}