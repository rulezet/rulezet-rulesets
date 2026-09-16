rule TTP_XOR_QUAD_CurrentVersionRun_deb7 {
  strings:
    $key_deb7 = { 8d d8 [2] a9 d6 [2] 82 fa [2] ac d8 [2] b8 c3 [2] b7 d9 [2] a9 c4 [2] ab c5 [2] b0 c3 [2] ac c4 [2] b0 eb }

  condition:
    any of them
}