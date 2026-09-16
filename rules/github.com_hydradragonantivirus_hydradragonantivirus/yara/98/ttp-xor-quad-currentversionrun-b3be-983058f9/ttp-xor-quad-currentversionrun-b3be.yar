rule TTP_XOR_QUAD_CurrentVersionRun_b3be {
  strings:
    $key_b3be = { e0 d1 [2] c4 df [2] ef f3 [2] c1 d1 [2] d5 ca [2] da d0 [2] c4 cd [2] c6 cc [2] dd ca [2] c1 cd [2] dd e2 }

  condition:
    any of them
}