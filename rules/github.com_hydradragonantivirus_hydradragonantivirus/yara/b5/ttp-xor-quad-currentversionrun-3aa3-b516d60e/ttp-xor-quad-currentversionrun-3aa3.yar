rule TTP_XOR_QUAD_CurrentVersionRun_3aa3 {
  strings:
    $key_3aa3 = { 69 cc [2] 4d c2 [2] 66 ee [2] 48 cc [2] 5c d7 [2] 53 cd [2] 4d d0 [2] 4f d1 [2] 54 d7 [2] 48 d0 [2] 54 ff }

  condition:
    any of them
}