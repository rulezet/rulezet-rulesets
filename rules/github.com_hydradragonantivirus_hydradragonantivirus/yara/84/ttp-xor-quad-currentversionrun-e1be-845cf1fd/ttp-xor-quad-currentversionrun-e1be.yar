rule TTP_XOR_QUAD_CurrentVersionRun_e1be {
  strings:
    $key_e1be = { b2 d1 [2] 96 df [2] bd f3 [2] 93 d1 [2] 87 ca [2] 88 d0 [2] 96 cd [2] 94 cc [2] 8f ca [2] 93 cd [2] 8f e2 }

  condition:
    any of them
}