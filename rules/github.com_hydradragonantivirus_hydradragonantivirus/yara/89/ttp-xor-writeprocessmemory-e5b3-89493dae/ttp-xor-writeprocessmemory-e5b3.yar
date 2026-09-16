rule TTP_XOR_WriteProcessMemory_e5b3 {
  strings:
    $key_e5b3 = { b2 c1 [2] 80 e3 [2] 86 d6 [2] a8 d6 [2] 97 ca }

  condition:
    any of them
}