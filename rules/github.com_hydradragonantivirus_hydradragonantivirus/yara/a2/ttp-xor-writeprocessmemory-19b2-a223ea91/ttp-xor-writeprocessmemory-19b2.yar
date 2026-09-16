rule TTP_XOR_WriteProcessMemory_19b2 {
  strings:
    $key_19b2 = { 4e c0 [2] 7c e2 [2] 7a d7 [2] 54 d7 [2] 6b cb }

  condition:
    any of them
}