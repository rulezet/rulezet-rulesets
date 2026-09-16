rule TTP_XOR_WriteProcessMemory_f9b2 {
  strings:
    $key_f9b2 = { ae c0 [2] 9c e2 [2] 9a d7 [2] b4 d7 [2] 8b cb }

  condition:
    any of them
}