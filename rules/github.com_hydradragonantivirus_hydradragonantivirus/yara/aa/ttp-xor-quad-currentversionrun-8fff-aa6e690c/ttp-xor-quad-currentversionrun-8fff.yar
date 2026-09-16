rule TTP_XOR_QUAD_CurrentVersionRun_8fff {
  strings:
    $key_8fff = { dc 90 [2] f8 9e [2] d3 b2 [2] fd 90 [2] e9 8b [2] e6 91 [2] f8 8c [2] fa 8d [2] e1 8b [2] fd 8c [2] e1 a3 }

  condition:
    any of them
}