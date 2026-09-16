rule TTP_XOR_QUAD_CurrentVersionRun_8dbf {
  strings:
    $key_8dbf = { de d0 [2] fa de [2] d1 f2 [2] ff d0 [2] eb cb [2] e4 d1 [2] fa cc [2] f8 cd [2] e3 cb [2] ff cc [2] e3 e3 }

  condition:
    any of them
}