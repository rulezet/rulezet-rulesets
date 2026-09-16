rule TTP_XOR_QUAD_CurrentVersionRun_63bf {
  strings:
    $key_63bf = { 30 d0 [2] 14 de [2] 3f f2 [2] 11 d0 [2] 05 cb [2] 0a d1 [2] 14 cc [2] 16 cd [2] 0d cb [2] 11 cc [2] 0d e3 }

  condition:
    any of them
}