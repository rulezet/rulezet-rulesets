rule TTP_XOR_QUAD_CurrentVersionRun_04be {
  strings:
    $key_04be = { 57 d1 [2] 73 df [2] 58 f3 [2] 76 d1 [2] 62 ca [2] 6d d0 [2] 73 cd [2] 71 cc [2] 6a ca [2] 76 cd [2] 6a e2 }

  condition:
    any of them
}