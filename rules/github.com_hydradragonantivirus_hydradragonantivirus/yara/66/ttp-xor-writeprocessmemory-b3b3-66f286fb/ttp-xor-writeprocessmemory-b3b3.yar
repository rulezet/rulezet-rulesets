rule TTP_XOR_WriteProcessMemory_b3b3 {
  strings:
    $key_b3b3 = { e4 c1 [2] d6 e3 [2] d0 d6 [2] fe d6 [2] c1 ca }

  condition:
    any of them
}