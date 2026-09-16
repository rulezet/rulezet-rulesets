rule TTP_XOR_QUAD_CurrentVersionRun_6aa3 {
  strings:
    $key_6aa3 = { 39 cc [2] 1d c2 [2] 36 ee [2] 18 cc [2] 0c d7 [2] 03 cd [2] 1d d0 [2] 1f d1 [2] 04 d7 [2] 18 d0 [2] 04 ff }

  condition:
    any of them
}