rule TTP_XOR_QUAD_CurrentVersionRun_b1ab {
  strings:
    $key_b1ab = { e2 c4 [2] c6 ca [2] ed e6 [2] c3 c4 [2] d7 df [2] d8 c5 [2] c6 d8 [2] c4 d9 [2] df df [2] c3 d8 [2] df f7 }

  condition:
    any of them
}