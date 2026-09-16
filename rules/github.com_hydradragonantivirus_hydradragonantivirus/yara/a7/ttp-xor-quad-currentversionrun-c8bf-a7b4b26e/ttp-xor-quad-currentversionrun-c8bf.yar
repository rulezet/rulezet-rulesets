rule TTP_XOR_QUAD_CurrentVersionRun_c8bf {
  strings:
    $key_c8bf = { 9b d0 [2] bf de [2] 94 f2 [2] ba d0 [2] ae cb [2] a1 d1 [2] bf cc [2] bd cd [2] a6 cb [2] ba cc [2] a6 e3 }

  condition:
    any of them
}