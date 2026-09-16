rule TTP_XOR_QUAD_CurrentVersionRun_21a8 {
  strings:
    $key_21a8 = { 72 c7 [2] 56 c9 [2] 7d e5 [2] 53 c7 [2] 47 dc [2] 48 c6 [2] 56 db [2] 54 da [2] 4f dc [2] 53 db [2] 4f f4 }

  condition:
    any of them
}