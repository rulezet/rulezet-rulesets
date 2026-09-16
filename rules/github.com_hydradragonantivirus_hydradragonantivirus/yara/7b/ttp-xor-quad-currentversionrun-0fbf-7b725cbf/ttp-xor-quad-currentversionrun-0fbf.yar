rule TTP_XOR_QUAD_CurrentVersionRun_0fbf {
  strings:
    $key_0fbf = { 5c d0 [2] 78 de [2] 53 f2 [2] 7d d0 [2] 69 cb [2] 66 d1 [2] 78 cc [2] 7a cd [2] 61 cb [2] 7d cc [2] 61 e3 }

  condition:
    any of them
}