rule TTP_XOR_QUAD_CurrentVersionRun_3fbe {
  strings:
    $key_3fbe = { 6c d1 [2] 48 df [2] 63 f3 [2] 4d d1 [2] 59 ca [2] 56 d0 [2] 48 cd [2] 4a cc [2] 51 ca [2] 4d cd [2] 51 e2 }

  condition:
    any of them
}