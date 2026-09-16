rule TTP_XOR_QUAD_CurrentVersionRun_22be {
  strings:
    $key_22be = { 71 d1 [2] 55 df [2] 7e f3 [2] 50 d1 [2] 44 ca [2] 4b d0 [2] 55 cd [2] 57 cc [2] 4c ca [2] 50 cd [2] 4c e2 }

  condition:
    any of them
}