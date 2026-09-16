rule TTP_XOR_QUAD_CurrentVersionRun_7c33 {
  strings:
    $key_7c33 = { 2f 5c [2] 0b 52 [2] 20 7e [2] 0e 5c [2] 1a 47 [2] 15 5d [2] 0b 40 [2] 09 41 [2] 12 47 [2] 0e 40 [2] 12 6f }

  condition:
    any of them
}