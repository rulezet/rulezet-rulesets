rule TTP_XOR_QUAD_CurrentVersionRun_9abf {
  strings:
    $key_9abf = { c9 d0 [2] ed de [2] c6 f2 [2] e8 d0 [2] fc cb [2] f3 d1 [2] ed cc [2] ef cd [2] f4 cb [2] e8 cc [2] f4 e3 }

  condition:
    any of them
}