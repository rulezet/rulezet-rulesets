rule TTP_XOR_QUAD_CurrentVersionRun_71be {
  strings:
    $key_71be = { 22 d1 [2] 06 df [2] 2d f3 [2] 03 d1 [2] 17 ca [2] 18 d0 [2] 06 cd [2] 04 cc [2] 1f ca [2] 03 cd [2] 1f e2 }

  condition:
    any of them
}