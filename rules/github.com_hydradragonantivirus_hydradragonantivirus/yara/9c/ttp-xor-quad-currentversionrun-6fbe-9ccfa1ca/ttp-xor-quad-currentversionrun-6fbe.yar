rule TTP_XOR_QUAD_CurrentVersionRun_6fbe {
  strings:
    $key_6fbe = { 3c d1 [2] 18 df [2] 33 f3 [2] 1d d1 [2] 09 ca [2] 06 d0 [2] 18 cd [2] 1a cc [2] 01 ca [2] 1d cd [2] 01 e2 }

  condition:
    any of them
}