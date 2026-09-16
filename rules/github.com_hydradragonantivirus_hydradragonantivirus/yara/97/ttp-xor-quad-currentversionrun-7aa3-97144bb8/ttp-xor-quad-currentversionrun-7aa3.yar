rule TTP_XOR_QUAD_CurrentVersionRun_7aa3 {
  strings:
    $key_7aa3 = { 29 cc [2] 0d c2 [2] 26 ee [2] 08 cc [2] 1c d7 [2] 13 cd [2] 0d d0 [2] 0f d1 [2] 14 d7 [2] 08 d0 [2] 14 ff }

  condition:
    any of them
}