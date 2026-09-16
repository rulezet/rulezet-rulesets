rule TTP_XOR_QUAD_CurrentVersionRun_13be {
  strings:
    $key_13be = { 40 d1 [2] 64 df [2] 4f f3 [2] 61 d1 [2] 75 ca [2] 7a d0 [2] 64 cd [2] 66 cc [2] 7d ca [2] 61 cd [2] 7d e2 }

  condition:
    any of them
}