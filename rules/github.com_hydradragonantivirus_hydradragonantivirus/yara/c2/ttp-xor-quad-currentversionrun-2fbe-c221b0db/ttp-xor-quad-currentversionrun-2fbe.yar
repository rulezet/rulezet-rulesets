rule TTP_XOR_QUAD_CurrentVersionRun_2fbe {
  strings:
    $key_2fbe = { 7c d1 [2] 58 df [2] 73 f3 [2] 5d d1 [2] 49 ca [2] 46 d0 [2] 58 cd [2] 5a cc [2] 41 ca [2] 5d cd [2] 41 e2 }

  condition:
    any of them
}