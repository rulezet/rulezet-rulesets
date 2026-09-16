rule TTP_XOR_QUAD_CurrentVersionRun_930c {
  strings:
    $key_930c = { c0 63 [2] e4 6d [2] cf 41 [2] e1 63 [2] f5 78 [2] fa 62 [2] e4 7f [2] e6 7e [2] fd 78 [2] e1 7f [2] fd 50 }

  condition:
    any of them
}