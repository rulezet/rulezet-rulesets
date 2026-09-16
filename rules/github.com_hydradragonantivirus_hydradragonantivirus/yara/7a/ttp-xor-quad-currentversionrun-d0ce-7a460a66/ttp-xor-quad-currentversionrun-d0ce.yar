rule TTP_XOR_QUAD_CurrentVersionRun_d0ce {
  strings:
    $key_d0ce = { 83 a1 [2] a7 af [2] 8c 83 [2] a2 a1 [2] b6 ba [2] b9 a0 [2] a7 bd [2] a5 bc [2] be ba [2] a2 bd [2] be 92 }

  condition:
    any of them
}