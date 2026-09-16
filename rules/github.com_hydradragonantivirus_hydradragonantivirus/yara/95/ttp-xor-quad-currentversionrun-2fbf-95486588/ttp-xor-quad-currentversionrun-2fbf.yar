rule TTP_XOR_QUAD_CurrentVersionRun_2fbf {
  strings:
    $key_2fbf = { 7c d0 [2] 58 de [2] 73 f2 [2] 5d d0 [2] 49 cb [2] 46 d1 [2] 58 cc [2] 5a cd [2] 41 cb [2] 5d cc [2] 41 e3 }

  condition:
    any of them
}