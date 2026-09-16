rule TTP_XOR_QUAD_CurrentVersionRun_93da {
  strings:
    $key_93da = { c0 b5 [2] e4 bb [2] cf 97 [2] e1 b5 [2] f5 ae [2] fa b4 [2] e4 a9 [2] e6 a8 [2] fd ae [2] e1 a9 [2] fd 86 }

  condition:
    any of them
}