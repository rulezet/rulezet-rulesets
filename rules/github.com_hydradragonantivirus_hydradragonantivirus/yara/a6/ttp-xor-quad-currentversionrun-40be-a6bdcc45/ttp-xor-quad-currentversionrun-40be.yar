rule TTP_XOR_QUAD_CurrentVersionRun_40be {
  strings:
    $key_40be = { 13 d1 [2] 37 df [2] 1c f3 [2] 32 d1 [2] 26 ca [2] 29 d0 [2] 37 cd [2] 35 cc [2] 2e ca [2] 32 cd [2] 2e e2 }

  condition:
    any of them
}