rule TTP_XOR_QUAD_CurrentVersionRun_73be {
  strings:
    $key_73be = { 20 d1 [2] 04 df [2] 2f f3 [2] 01 d1 [2] 15 ca [2] 1a d0 [2] 04 cd [2] 06 cc [2] 1d ca [2] 01 cd [2] 1d e2 }

  condition:
    any of them
}