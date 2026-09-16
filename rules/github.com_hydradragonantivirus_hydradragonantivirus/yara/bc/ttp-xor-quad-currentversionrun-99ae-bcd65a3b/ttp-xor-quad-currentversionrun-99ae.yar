rule TTP_XOR_QUAD_CurrentVersionRun_99ae {
  strings:
    $key_99ae = { ca c1 [2] ee cf [2] c5 e3 [2] eb c1 [2] ff da [2] f0 c0 [2] ee dd [2] ec dc [2] f7 da [2] eb dd [2] f7 f2 }

  condition:
    any of them
}