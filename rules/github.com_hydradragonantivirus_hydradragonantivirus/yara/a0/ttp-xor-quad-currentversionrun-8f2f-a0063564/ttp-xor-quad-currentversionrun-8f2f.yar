rule TTP_XOR_QUAD_CurrentVersionRun_8f2f {
  strings:
    $key_8f2f = { dc 40 [2] f8 4e [2] d3 62 [2] fd 40 [2] e9 5b [2] e6 41 [2] f8 5c [2] fa 5d [2] e1 5b [2] fd 5c [2] e1 73 }

  condition:
    any of them
}