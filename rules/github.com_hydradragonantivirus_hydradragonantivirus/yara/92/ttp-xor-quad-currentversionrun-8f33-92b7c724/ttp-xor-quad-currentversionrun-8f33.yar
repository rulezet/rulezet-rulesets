rule TTP_XOR_QUAD_CurrentVersionRun_8f33 {
  strings:
    $key_8f33 = { dc 5c [2] f8 52 [2] d3 7e [2] fd 5c [2] e9 47 [2] e6 5d [2] f8 40 [2] fa 41 [2] e1 47 [2] fd 40 [2] e1 6f }

  condition:
    any of them
}