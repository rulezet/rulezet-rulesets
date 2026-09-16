rule TTP_XOR_QUAD_CurrentVersionRun_41be {
  strings:
    $key_41be = { 12 d1 [2] 36 df [2] 1d f3 [2] 33 d1 [2] 27 ca [2] 28 d0 [2] 36 cd [2] 34 cc [2] 2f ca [2] 33 cd [2] 2f e2 }

  condition:
    any of them
}