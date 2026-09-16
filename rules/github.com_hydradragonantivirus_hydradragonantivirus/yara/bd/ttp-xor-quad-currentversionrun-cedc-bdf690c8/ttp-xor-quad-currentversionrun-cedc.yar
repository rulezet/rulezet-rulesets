rule TTP_XOR_QUAD_CurrentVersionRun_cedc {
  strings:
    $key_cedc = { 9d b3 [2] b9 bd [2] 92 91 [2] bc b3 [2] a8 a8 [2] a7 b2 [2] b9 af [2] bb ae [2] a0 a8 [2] bc af [2] a0 80 }

  condition:
    any of them
}