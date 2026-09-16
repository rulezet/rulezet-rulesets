rule TTP_XOR_QUAD_CurrentVersionRun_b1be {
  strings:
    $key_b1be = { e2 d1 [2] c6 df [2] ed f3 [2] c3 d1 [2] d7 ca [2] d8 d0 [2] c6 cd [2] c4 cc [2] df ca [2] c3 cd [2] df e2 }

  condition:
    any of them
}