rule TTP_XOR_QUAD_CurrentVersionRun_50be {
  strings:
    $key_50be = { 03 d1 [2] 27 df [2] 0c f3 [2] 22 d1 [2] 36 ca [2] 39 d0 [2] 27 cd [2] 25 cc [2] 3e ca [2] 22 cd [2] 3e e2 }

  condition:
    any of them
}