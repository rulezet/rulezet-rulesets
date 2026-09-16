rule TTP_XOR_WriteProcessMemory_e5c3 {
  strings:
    $key_e5c3 = { b2 b1 [2] 80 93 [2] 86 a6 [2] a8 a6 [2] 97 ba }

  condition:
    any of them
}