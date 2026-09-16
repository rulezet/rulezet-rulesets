rule TTP_XOR_QUAD_CurrentVersionRun_8f0c {
  strings:
    $key_8f0c = { dc 63 [2] f8 6d [2] d3 41 [2] fd 63 [2] e9 78 [2] e6 62 [2] f8 7f [2] fa 7e [2] e1 78 [2] fd 7f [2] e1 50 }

  condition:
    any of them
}