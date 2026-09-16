rule TTP_XOR_QUAD_CurrentVersionRun_1abf {
  strings:
    $key_1abf = { 49 d0 [2] 6d de [2] 46 f2 [2] 68 d0 [2] 7c cb [2] 73 d1 [2] 6d cc [2] 6f cd [2] 74 cb [2] 68 cc [2] 74 e3 }

  condition:
    any of them
}