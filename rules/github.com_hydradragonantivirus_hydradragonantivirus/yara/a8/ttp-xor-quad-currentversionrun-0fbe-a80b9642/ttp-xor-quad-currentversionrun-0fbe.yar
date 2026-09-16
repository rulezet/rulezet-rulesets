rule TTP_XOR_QUAD_CurrentVersionRun_0fbe {
  strings:
    $key_0fbe = { 5c d1 [2] 78 df [2] 53 f3 [2] 7d d1 [2] 69 ca [2] 66 d0 [2] 78 cd [2] 7a cc [2] 61 ca [2] 7d cd [2] 61 e2 }

  condition:
    any of them
}