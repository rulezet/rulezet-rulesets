rule TTP_XOR_QUAD_CurrentVersionRun_54bf {
  strings:
    $key_54bf = { 07 d0 [2] 23 de [2] 08 f2 [2] 26 d0 [2] 32 cb [2] 3d d1 [2] 23 cc [2] 21 cd [2] 3a cb [2] 26 cc [2] 3a e3 }

  condition:
    any of them
}