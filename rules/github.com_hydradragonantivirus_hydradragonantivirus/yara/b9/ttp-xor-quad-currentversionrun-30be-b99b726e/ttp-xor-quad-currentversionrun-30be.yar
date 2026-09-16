rule TTP_XOR_QUAD_CurrentVersionRun_30be {
  strings:
    $key_30be = { 63 d1 [2] 47 df [2] 6c f3 [2] 42 d1 [2] 56 ca [2] 59 d0 [2] 47 cd [2] 45 cc [2] 5e ca [2] 42 cd [2] 5e e2 }

  condition:
    any of them
}