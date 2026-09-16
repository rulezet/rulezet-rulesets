rule TTP_XOR_QUAD_CurrentVersionRun_76be {
  strings:
    $key_76be = { 25 d1 [2] 01 df [2] 2a f3 [2] 04 d1 [2] 10 ca [2] 1f d0 [2] 01 cd [2] 03 cc [2] 18 ca [2] 04 cd [2] 18 e2 }

  condition:
    any of them
}