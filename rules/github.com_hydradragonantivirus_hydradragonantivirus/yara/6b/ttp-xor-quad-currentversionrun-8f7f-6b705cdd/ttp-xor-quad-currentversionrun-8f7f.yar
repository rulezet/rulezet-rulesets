rule TTP_XOR_QUAD_CurrentVersionRun_8f7f {
  strings:
    $key_8f7f = { dc 10 [2] f8 1e [2] d3 32 [2] fd 10 [2] e9 0b [2] e6 11 [2] f8 0c [2] fa 0d [2] e1 0b [2] fd 0c [2] e1 23 }

  condition:
    any of them
}