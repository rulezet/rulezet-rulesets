rule TTP_XOR_QUAD_CurrentVersionRun_1fbe {
  strings:
    $key_1fbe = { 4c d1 [2] 68 df [2] 43 f3 [2] 6d d1 [2] 79 ca [2] 76 d0 [2] 68 cd [2] 6a cc [2] 71 ca [2] 6d cd [2] 71 e2 }

  condition:
    any of them
}