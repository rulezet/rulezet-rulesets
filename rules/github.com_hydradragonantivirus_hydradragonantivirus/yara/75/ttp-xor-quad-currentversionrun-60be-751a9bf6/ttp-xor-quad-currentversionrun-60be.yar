rule TTP_XOR_QUAD_CurrentVersionRun_60be {
  strings:
    $key_60be = { 33 d1 [2] 17 df [2] 3c f3 [2] 12 d1 [2] 06 ca [2] 09 d0 [2] 17 cd [2] 15 cc [2] 0e ca [2] 12 cd [2] 0e e2 }

  condition:
    any of them
}