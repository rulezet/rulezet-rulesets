rule TTP_XOR_QUAD_CurrentVersionRun_c2bb {
  strings:
    $key_c2bb = { 91 d4 [2] b5 da [2] 9e f6 [2] b0 d4 [2] a4 cf [2] ab d5 [2] b5 c8 [2] b7 c9 [2] ac cf [2] b0 c8 [2] ac e7 }

  condition:
    any of them
}