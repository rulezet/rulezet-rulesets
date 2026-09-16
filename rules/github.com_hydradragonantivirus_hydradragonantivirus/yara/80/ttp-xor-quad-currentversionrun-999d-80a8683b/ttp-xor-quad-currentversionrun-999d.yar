rule TTP_XOR_QUAD_CurrentVersionRun_999d {
  strings:
    $key_999d = { ca f2 [2] ee fc [2] c5 d0 [2] eb f2 [2] ff e9 [2] f0 f3 [2] ee ee [2] ec ef [2] f7 e9 [2] eb ee [2] f7 c1 }

  condition:
    any of them
}