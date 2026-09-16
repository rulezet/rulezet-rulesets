rule TTP_XOR_QUAD_CurrentVersionRun_936c {
  strings:
    $key_936c = { c0 03 [2] e4 0d [2] cf 21 [2] e1 03 [2] f5 18 [2] fa 02 [2] e4 1f [2] e6 1e [2] fd 18 [2] e1 1f [2] fd 30 }

  condition:
    any of them
}