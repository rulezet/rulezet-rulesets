rule TTP_XOR_QUAD_CurrentVersionRun_936b {
  strings:
    $key_936b = { c0 04 [2] e4 0a [2] cf 26 [2] e1 04 [2] f5 1f [2] fa 05 [2] e4 18 [2] e6 19 [2] fd 1f [2] e1 18 [2] fd 37 }

  condition:
    any of them
}