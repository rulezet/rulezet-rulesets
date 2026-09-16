rule TTP_XOR_QUAD_CurrentVersionRun_b7be {
  strings:
    $key_b7be = { e4 d1 [2] c0 df [2] eb f3 [2] c5 d1 [2] d1 ca [2] de d0 [2] c0 cd [2] c2 cc [2] d9 ca [2] c5 cd [2] d9 e2 }

  condition:
    any of them
}