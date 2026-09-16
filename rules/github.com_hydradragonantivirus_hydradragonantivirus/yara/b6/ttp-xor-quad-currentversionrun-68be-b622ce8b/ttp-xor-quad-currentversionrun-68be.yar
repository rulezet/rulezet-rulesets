rule TTP_XOR_QUAD_CurrentVersionRun_68be {
  strings:
    $key_68be = { 3b d1 [2] 1f df [2] 34 f3 [2] 1a d1 [2] 0e ca [2] 01 d0 [2] 1f cd [2] 1d cc [2] 06 ca [2] 1a cd [2] 06 e2 }

  condition:
    any of them
}