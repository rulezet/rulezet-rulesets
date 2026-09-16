rule TTP_XOR_QUAD_CurrentVersionRun_cedd {
  strings:
    $key_cedd = { 9d b2 [2] b9 bc [2] 92 90 [2] bc b2 [2] a8 a9 [2] a7 b3 [2] b9 ae [2] bb af [2] a0 a9 [2] bc ae [2] a0 81 }

  condition:
    any of them
}