rule TTP_XOR_WriteProcessMemory_c0b3 {
  strings:
    $key_c0b3 = { 97 c1 [2] a5 e3 [2] a3 d6 [2] 8d d6 [2] b2 ca }

  condition:
    any of them
}