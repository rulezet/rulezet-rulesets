rule TTP_XOR_QUAD_CurrentVersionRun_52bf {
  strings:
    $key_52bf = { 01 d0 [2] 25 de [2] 0e f2 [2] 20 d0 [2] 34 cb [2] 3b d1 [2] 25 cc [2] 27 cd [2] 3c cb [2] 20 cc [2] 3c e3 }

  condition:
    any of them
}