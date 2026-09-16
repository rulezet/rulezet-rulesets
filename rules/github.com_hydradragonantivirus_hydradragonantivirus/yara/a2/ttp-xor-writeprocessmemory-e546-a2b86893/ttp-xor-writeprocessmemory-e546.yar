rule TTP_XOR_WriteProcessMemory_e546 {
  strings:
    $key_e546 = { b2 34 [2] 80 16 [2] 86 23 [2] a8 23 [2] 97 3f }

  condition:
    any of them
}