rule TTP_XOR_QUAD_CurrentVersionRun_cebb {
  strings:
    $key_cebb = { 9d d4 [2] b9 da [2] 92 f6 [2] bc d4 [2] a8 cf [2] a7 d5 [2] b9 c8 [2] bb c9 [2] a0 cf [2] bc c8 [2] a0 e7 }

  condition:
    any of them
}