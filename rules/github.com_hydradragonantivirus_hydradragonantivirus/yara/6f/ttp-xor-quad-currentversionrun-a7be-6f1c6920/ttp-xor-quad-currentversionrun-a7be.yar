rule TTP_XOR_QUAD_CurrentVersionRun_a7be {
  strings:
    $key_a7be = { f4 d1 [2] d0 df [2] fb f3 [2] d5 d1 [2] c1 ca [2] ce d0 [2] d0 cd [2] d2 cc [2] c9 ca [2] d5 cd [2] c9 e2 }

  condition:
    any of them
}