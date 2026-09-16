rule TTP_XOR_QUAD_CurrentVersionRun_6abf {
  strings:
    $key_6abf = { 39 d0 [2] 1d de [2] 36 f2 [2] 18 d0 [2] 0c cb [2] 03 d1 [2] 1d cc [2] 1f cd [2] 04 cb [2] 18 cc [2] 04 e3 }

  condition:
    any of them
}