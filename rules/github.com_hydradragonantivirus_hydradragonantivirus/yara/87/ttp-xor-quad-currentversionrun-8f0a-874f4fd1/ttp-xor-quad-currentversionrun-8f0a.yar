rule TTP_XOR_QUAD_CurrentVersionRun_8f0a {
  strings:
    $key_8f0a = { dc 65 [2] f8 6b [2] d3 47 [2] fd 65 [2] e9 7e [2] e6 64 [2] f8 79 [2] fa 78 [2] e1 7e [2] fd 79 [2] e1 56 }

  condition:
    any of them
}