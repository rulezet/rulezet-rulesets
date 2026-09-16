rule TTP_XOR_WriteProcessMemory_b7b3 {
  strings:
    $key_b7b3 = { e0 c1 [2] d2 e3 [2] d4 d6 [2] fa d6 [2] c5 ca }

  condition:
    any of them
}