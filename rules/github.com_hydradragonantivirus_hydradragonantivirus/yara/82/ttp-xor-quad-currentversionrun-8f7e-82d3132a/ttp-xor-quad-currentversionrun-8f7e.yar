rule TTP_XOR_QUAD_CurrentVersionRun_8f7e {
  strings:
    $key_8f7e = { dc 11 [2] f8 1f [2] d3 33 [2] fd 11 [2] e9 0a [2] e6 10 [2] f8 0d [2] fa 0c [2] e1 0a [2] fd 0d [2] e1 22 }

  condition:
    any of them
}