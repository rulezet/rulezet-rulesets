rule TTP_XOR_QUAD_CurrentVersionRun_b2be {
  strings:
    $key_b2be = { e1 d1 [2] c5 df [2] ee f3 [2] c0 d1 [2] d4 ca [2] db d0 [2] c5 cd [2] c7 cc [2] dc ca [2] c0 cd [2] dc e2 }

  condition:
    any of them
}