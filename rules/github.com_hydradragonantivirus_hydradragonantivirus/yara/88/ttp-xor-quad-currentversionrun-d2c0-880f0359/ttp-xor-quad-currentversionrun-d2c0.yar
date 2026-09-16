rule TTP_XOR_QUAD_CurrentVersionRun_d2c0 {
  strings:
    $key_d2c0 = { 81 af [2] a5 a1 [2] 8e 8d [2] a0 af [2] b4 b4 [2] bb ae [2] a5 b3 [2] a7 b2 [2] bc b4 [2] a0 b3 [2] bc 9c }

  condition:
    any of them
}