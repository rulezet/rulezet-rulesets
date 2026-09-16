rule TTP_XOR_QUAD_CurrentVersionRun_5da3 {
  strings:
    $key_5da3 = { 0e cc [2] 2a c2 [2] 01 ee [2] 2f cc [2] 3b d7 [2] 34 cd [2] 2a d0 [2] 28 d1 [2] 33 d7 [2] 2f d0 [2] 33 ff }

  condition:
    any of them
}