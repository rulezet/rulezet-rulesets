rule TTP_XOR_QUAD_CurrentVersionRun_5aa3 {
  strings:
    $key_5aa3 = { 09 cc [2] 2d c2 [2] 06 ee [2] 28 cc [2] 3c d7 [2] 33 cd [2] 2d d0 [2] 2f d1 [2] 34 d7 [2] 28 d0 [2] 34 ff }

  condition:
    any of them
}