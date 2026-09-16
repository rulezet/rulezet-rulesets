rule TTP_XOR_QUAD_CurrentVersionRun_e4bf {
  strings:
    $key_e4bf = { b7 d0 [2] 93 de [2] b8 f2 [2] 96 d0 [2] 82 cb [2] 8d d1 [2] 93 cc [2] 91 cd [2] 8a cb [2] 96 cc [2] 8a e3 }

  condition:
    any of them
}