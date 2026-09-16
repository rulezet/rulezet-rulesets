rule TTP_XOR_QUAD_CurrentVersionRun_35bf {
  strings:
    $key_35bf = { 66 d0 [2] 42 de [2] 69 f2 [2] 47 d0 [2] 53 cb [2] 5c d1 [2] 42 cc [2] 40 cd [2] 5b cb [2] 47 cc [2] 5b e3 }

  condition:
    any of them
}