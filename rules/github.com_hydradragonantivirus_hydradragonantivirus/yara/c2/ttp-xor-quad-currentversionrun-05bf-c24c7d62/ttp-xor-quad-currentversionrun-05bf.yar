rule TTP_XOR_QUAD_CurrentVersionRun_05bf {
  strings:
    $key_05bf = { 56 d0 [2] 72 de [2] 59 f2 [2] 77 d0 [2] 63 cb [2] 6c d1 [2] 72 cc [2] 70 cd [2] 6b cb [2] 77 cc [2] 6b e3 }

  condition:
    any of them
}