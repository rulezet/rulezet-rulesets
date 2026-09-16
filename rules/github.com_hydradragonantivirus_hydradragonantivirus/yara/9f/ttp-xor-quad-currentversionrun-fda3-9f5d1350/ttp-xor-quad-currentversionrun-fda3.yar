rule TTP_XOR_QUAD_CurrentVersionRun_fda3 {
  strings:
    $key_fda3 = { ae cc [2] 8a c2 [2] a1 ee [2] 8f cc [2] 9b d7 [2] 94 cd [2] 8a d0 [2] 88 d1 [2] 93 d7 [2] 8f d0 [2] 93 ff }

  condition:
    any of them
}