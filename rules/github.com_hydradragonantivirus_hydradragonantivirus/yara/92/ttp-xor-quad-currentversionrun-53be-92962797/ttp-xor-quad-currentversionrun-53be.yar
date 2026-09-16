rule TTP_XOR_QUAD_CurrentVersionRun_53be {
  strings:
    $key_53be = { 00 d1 [2] 24 df [2] 0f f3 [2] 21 d1 [2] 35 ca [2] 3a d0 [2] 24 cd [2] 26 cc [2] 3d ca [2] 21 cd [2] 3d e2 }

  condition:
    any of them
}