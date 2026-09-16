rule TTP_XOR_QUAD_CurrentVersionRun_1c33 {
  strings:
    $key_1c33 = { 4f 5c [2] 6b 52 [2] 40 7e [2] 6e 5c [2] 7a 47 [2] 75 5d [2] 6b 40 [2] 69 41 [2] 72 47 [2] 6e 40 [2] 72 6f }

  condition:
    any of them
}