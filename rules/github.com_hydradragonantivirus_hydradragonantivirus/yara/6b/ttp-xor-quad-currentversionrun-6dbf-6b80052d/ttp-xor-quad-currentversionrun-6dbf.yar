rule TTP_XOR_QUAD_CurrentVersionRun_6dbf {
  strings:
    $key_6dbf = { 3e d0 [2] 1a de [2] 31 f2 [2] 1f d0 [2] 0b cb [2] 04 d1 [2] 1a cc [2] 18 cd [2] 03 cb [2] 1f cc [2] 03 e3 }

  condition:
    any of them
}