rule TTP_XOR_QUAD_CurrentVersionRun_1dbf {
  strings:
    $key_1dbf = { 4e d0 [2] 6a de [2] 41 f2 [2] 6f d0 [2] 7b cb [2] 74 d1 [2] 6a cc [2] 68 cd [2] 73 cb [2] 6f cc [2] 73 e3 }

  condition:
    any of them
}