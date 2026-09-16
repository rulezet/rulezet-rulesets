rule TTP_XOR_QUAD_CurrentVersionRun_937e {
  strings:
    $key_937e = { c0 11 [2] e4 1f [2] cf 33 [2] e1 11 [2] f5 0a [2] fa 10 [2] e4 0d [2] e6 0c [2] fd 0a [2] e1 0d [2] fd 22 }

  condition:
    any of them
}