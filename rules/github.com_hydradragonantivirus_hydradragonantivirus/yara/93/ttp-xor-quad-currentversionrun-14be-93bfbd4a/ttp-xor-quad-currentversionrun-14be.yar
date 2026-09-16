rule TTP_XOR_QUAD_CurrentVersionRun_14be {
  strings:
    $key_14be = { 47 d1 [2] 63 df [2] 48 f3 [2] 66 d1 [2] 72 ca [2] 7d d0 [2] 63 cd [2] 61 cc [2] 7a ca [2] 66 cd [2] 7a e2 }

  condition:
    any of them
}