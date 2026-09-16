rule TTP_XOR_WriteProcessMemory_b1b3 {
  strings:
    $key_b1b3 = { e6 c1 [2] d4 e3 [2] d2 d6 [2] fc d6 [2] c3 ca }

  condition:
    any of them
}