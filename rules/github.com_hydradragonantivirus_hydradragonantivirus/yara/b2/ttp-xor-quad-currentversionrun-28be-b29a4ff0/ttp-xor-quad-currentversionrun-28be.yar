rule TTP_XOR_QUAD_CurrentVersionRun_28be {
  strings:
    $key_28be = { 7b d1 [2] 5f df [2] 74 f3 [2] 5a d1 [2] 4e ca [2] 41 d0 [2] 5f cd [2] 5d cc [2] 46 ca [2] 5a cd [2] 46 e2 }

  condition:
    any of them
}