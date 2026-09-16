rule TTP_XOR_QUAD_CurrentVersionRun_38be {
  strings:
    $key_38be = { 6b d1 [2] 4f df [2] 64 f3 [2] 4a d1 [2] 5e ca [2] 51 d0 [2] 4f cd [2] 4d cc [2] 56 ca [2] 4a cd [2] 56 e2 }

  condition:
    any of them
}