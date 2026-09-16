rule TTP_XOR_QUAD_CurrentVersionRun_4aa3 {
  strings:
    $key_4aa3 = { 19 cc [2] 3d c2 [2] 16 ee [2] 38 cc [2] 2c d7 [2] 23 cd [2] 3d d0 [2] 3f d1 [2] 24 d7 [2] 38 d0 [2] 24 ff }

  condition:
    any of them
}