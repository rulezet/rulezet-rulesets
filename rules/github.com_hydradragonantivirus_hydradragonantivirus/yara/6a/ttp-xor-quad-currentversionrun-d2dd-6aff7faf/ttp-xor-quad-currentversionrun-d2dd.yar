rule TTP_XOR_QUAD_CurrentVersionRun_d2dd {
  strings:
    $key_d2dd = { 81 b2 [2] a5 bc [2] 8e 90 [2] a0 b2 [2] b4 a9 [2] bb b3 [2] a5 ae [2] a7 af [2] bc a9 [2] a0 ae [2] bc 81 }

  condition:
    any of them
}