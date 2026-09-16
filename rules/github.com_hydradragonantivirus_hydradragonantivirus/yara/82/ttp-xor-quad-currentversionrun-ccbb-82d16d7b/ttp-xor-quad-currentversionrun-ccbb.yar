rule TTP_XOR_QUAD_CurrentVersionRun_ccbb {
  strings:
    $key_ccbb = { 9f d4 [2] bb da [2] 90 f6 [2] be d4 [2] aa cf [2] a5 d5 [2] bb c8 [2] b9 c9 [2] a2 cf [2] be c8 [2] a2 e7 }

  condition:
    any of them
}