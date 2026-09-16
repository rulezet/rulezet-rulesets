rule TTP_XOR_QUAD_CurrentVersionRun_4fbe {
  strings:
    $key_4fbe = { 1c d1 [2] 38 df [2] 13 f3 [2] 3d d1 [2] 29 ca [2] 26 d0 [2] 38 cd [2] 3a cc [2] 21 ca [2] 3d cd [2] 21 e2 }

  condition:
    any of them
}