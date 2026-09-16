rule TTP_XOR_QUAD_CurrentVersionRun_0dbf {
  strings:
    $key_0dbf = { 5e d0 [2] 7a de [2] 51 f2 [2] 7f d0 [2] 6b cb [2] 64 d1 [2] 7a cc [2] 78 cd [2] 63 cb [2] 7f cc [2] 63 e3 }

  condition:
    any of them
}