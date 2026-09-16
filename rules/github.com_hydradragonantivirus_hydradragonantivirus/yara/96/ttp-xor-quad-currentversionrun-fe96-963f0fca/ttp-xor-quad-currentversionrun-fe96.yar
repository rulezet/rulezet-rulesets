rule TTP_XOR_QUAD_CurrentVersionRun_fe96 {
  strings:
    $key_fe96 = { ad f9 [2] 89 f7 [2] a2 db [2] 8c f9 [2] 98 e2 [2] 97 f8 [2] 89 e5 [2] 8b e4 [2] 90 e2 [2] 8c e5 [2] 90 ca }

  condition:
    any of them
}