rule TTP_XOR_QUAD_CurrentVersionRun_44be {
  strings:
    $key_44be = { 17 d1 [2] 33 df [2] 18 f3 [2] 36 d1 [2] 22 ca [2] 2d d0 [2] 33 cd [2] 31 cc [2] 2a ca [2] 36 cd [2] 2a e2 }

  condition:
    any of them
}