rule TTP_XOR_QUAD_CurrentVersionRun_931e {
  strings:
    $key_931e = { c0 71 [2] e4 7f [2] cf 53 [2] e1 71 [2] f5 6a [2] fa 70 [2] e4 6d [2] e6 6c [2] fd 6a [2] e1 6d [2] fd 42 }

  condition:
    any of them
}