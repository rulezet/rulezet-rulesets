rule TTP_XOR_WriteProcessMemory_c0b2 {
  strings:
    $key_c0b2 = { 97 c0 [2] a5 e2 [2] a3 d7 [2] 8d d7 [2] b2 cb }

  condition:
    any of them
}