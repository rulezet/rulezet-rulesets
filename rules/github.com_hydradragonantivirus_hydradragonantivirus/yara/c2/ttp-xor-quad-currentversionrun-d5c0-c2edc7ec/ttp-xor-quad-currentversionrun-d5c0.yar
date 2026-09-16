rule TTP_XOR_QUAD_CurrentVersionRun_d5c0 {
  strings:
    $key_d5c0 = { 86 af [2] a2 a1 [2] 89 8d [2] a7 af [2] b3 b4 [2] bc ae [2] a2 b3 [2] a0 b2 [2] bb b4 [2] a7 b3 [2] bb 9c }

  condition:
    any of them
}