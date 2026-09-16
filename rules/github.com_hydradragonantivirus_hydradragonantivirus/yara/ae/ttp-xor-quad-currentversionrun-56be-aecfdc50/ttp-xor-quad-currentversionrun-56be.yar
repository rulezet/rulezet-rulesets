rule TTP_XOR_QUAD_CurrentVersionRun_56be {
  strings:
    $key_56be = { 05 d1 [2] 21 df [2] 0a f3 [2] 24 d1 [2] 30 ca [2] 3f d0 [2] 21 cd [2] 23 cc [2] 38 ca [2] 24 cd [2] 38 e2 }

  condition:
    any of them
}