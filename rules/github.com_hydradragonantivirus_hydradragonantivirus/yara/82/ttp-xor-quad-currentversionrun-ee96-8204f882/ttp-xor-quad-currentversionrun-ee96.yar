rule TTP_XOR_QUAD_CurrentVersionRun_ee96 {
  strings:
    $key_ee96 = { bd f9 [2] 99 f7 [2] b2 db [2] 9c f9 [2] 88 e2 [2] 87 f8 [2] 99 e5 [2] 9b e4 [2] 80 e2 [2] 9c e5 [2] 80 ca }

  condition:
    any of them
}