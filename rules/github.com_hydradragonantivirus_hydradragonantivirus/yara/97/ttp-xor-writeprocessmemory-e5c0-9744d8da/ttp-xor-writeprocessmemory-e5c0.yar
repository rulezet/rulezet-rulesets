rule TTP_XOR_WriteProcessMemory_e5c0 {
  strings:
    $key_e5c0 = { b2 b2 [2] 80 90 [2] 86 a5 [2] a8 a5 [2] 97 b9 }

  condition:
    any of them
}