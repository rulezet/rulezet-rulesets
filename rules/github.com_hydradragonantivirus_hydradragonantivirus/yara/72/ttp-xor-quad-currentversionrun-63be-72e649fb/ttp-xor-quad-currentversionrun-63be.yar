rule TTP_XOR_QUAD_CurrentVersionRun_63be {
  strings:
    $key_63be = { 30 d1 [2] 14 df [2] 3f f3 [2] 11 d1 [2] 05 ca [2] 0a d0 [2] 14 cd [2] 16 cc [2] 0d ca [2] 11 cd [2] 0d e2 }

  condition:
    any of them
}