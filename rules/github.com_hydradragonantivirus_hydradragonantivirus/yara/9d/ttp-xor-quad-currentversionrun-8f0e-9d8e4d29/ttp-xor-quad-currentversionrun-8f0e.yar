rule TTP_XOR_QUAD_CurrentVersionRun_8f0e {
  strings:
    $key_8f0e = { dc 61 [2] f8 6f [2] d3 43 [2] fd 61 [2] e9 7a [2] e6 60 [2] f8 7d [2] fa 7c [2] e1 7a [2] fd 7d [2] e1 52 }

  condition:
    any of them
}