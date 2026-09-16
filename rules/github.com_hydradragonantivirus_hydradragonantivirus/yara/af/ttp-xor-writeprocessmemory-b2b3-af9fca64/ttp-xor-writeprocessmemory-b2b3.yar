rule TTP_XOR_WriteProcessMemory_b2b3 {
  strings:
    $key_b2b3 = { e5 c1 [2] d7 e3 [2] d1 d6 [2] ff d6 [2] c0 ca }

  condition:
    any of them
}