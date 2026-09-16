rule TTP_XOR_WriteProcessMemory_c0b5 {
  strings:
    $key_c0b5 = { 97 c7 [2] a5 e5 [2] a3 d0 [2] 8d d0 [2] b2 cc }

  condition:
    any of them
}