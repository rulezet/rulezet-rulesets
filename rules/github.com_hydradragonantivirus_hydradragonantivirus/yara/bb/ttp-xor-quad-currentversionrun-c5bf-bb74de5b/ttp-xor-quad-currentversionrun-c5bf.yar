rule TTP_XOR_QUAD_CurrentVersionRun_c5bf {
  strings:
    $key_c5bf = { 96 d0 [2] b2 de [2] 99 f2 [2] b7 d0 [2] a3 cb [2] ac d1 [2] b2 cc [2] b0 cd [2] ab cb [2] b7 cc [2] ab e3 }

  condition:
    any of them
}