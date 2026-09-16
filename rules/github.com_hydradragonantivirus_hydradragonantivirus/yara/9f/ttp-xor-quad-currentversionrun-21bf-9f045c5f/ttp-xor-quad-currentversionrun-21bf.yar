rule TTP_XOR_QUAD_CurrentVersionRun_21bf {
  strings:
    $key_21bf = { 72 d0 [2] 56 de [2] 7d f2 [2] 53 d0 [2] 47 cb [2] 48 d1 [2] 56 cc [2] 54 cd [2] 4f cb [2] 53 cc [2] 4f e3 }

  condition:
    any of them
}