rule TTP_XOR_QUAD_CurrentVersionRun_03be {
  strings:
    $key_03be = { 50 d1 [2] 74 df [2] 5f f3 [2] 71 d1 [2] 65 ca [2] 6a d0 [2] 74 cd [2] 76 cc [2] 6d ca [2] 71 cd [2] 6d e2 }

  condition:
    any of them
}