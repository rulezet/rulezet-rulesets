rule TTP_XOR_QUAD_CurrentVersionRun_d4be {
  strings:
    $key_d4be = { 87 d1 [2] a3 df [2] 88 f3 [2] a6 d1 [2] b2 ca [2] bd d0 [2] a3 cd [2] a1 cc [2] ba ca [2] a6 cd [2] ba e2 }

  condition:
    any of them
}