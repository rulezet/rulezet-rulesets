rule TTP_XOR_QUAD_CurrentVersionRun_76bf {
  strings:
    $key_76bf = { 25 d0 [2] 01 de [2] 2a f2 [2] 04 d0 [2] 10 cb [2] 1f d1 [2] 01 cc [2] 03 cd [2] 18 cb [2] 04 cc [2] 18 e3 }

  condition:
    any of them
}