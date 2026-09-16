rule TTP_XOR_QUAD_CurrentVersionRun_dbbf {
  strings:
    $key_dbbf = { 88 d0 [2] ac de [2] 87 f2 [2] a9 d0 [2] bd cb [2] b2 d1 [2] ac cc [2] ae cd [2] b5 cb [2] a9 cc [2] b5 e3 }

  condition:
    any of them
}