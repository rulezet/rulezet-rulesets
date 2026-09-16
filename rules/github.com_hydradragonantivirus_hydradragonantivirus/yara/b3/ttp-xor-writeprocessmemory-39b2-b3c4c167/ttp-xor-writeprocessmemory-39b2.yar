rule TTP_XOR_WriteProcessMemory_39b2 {
  strings:
    $key_39b2 = { 6e c0 [2] 5c e2 [2] 5a d7 [2] 74 d7 [2] 4b cb }

  condition:
    any of them
}