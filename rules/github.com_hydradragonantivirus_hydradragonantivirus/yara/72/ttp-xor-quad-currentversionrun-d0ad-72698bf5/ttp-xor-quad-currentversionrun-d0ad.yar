rule TTP_XOR_QUAD_CurrentVersionRun_d0ad {
  strings:
    $key_d0ad = { 83 c2 [2] a7 cc [2] 8c e0 [2] a2 c2 [2] b6 d9 [2] b9 c3 [2] a7 de [2] a5 df [2] be d9 [2] a2 de [2] be f1 }

  condition:
    any of them
}