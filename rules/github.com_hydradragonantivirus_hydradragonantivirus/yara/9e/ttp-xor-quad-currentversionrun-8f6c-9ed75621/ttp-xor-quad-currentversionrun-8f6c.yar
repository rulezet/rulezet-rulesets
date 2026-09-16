rule TTP_XOR_QUAD_CurrentVersionRun_8f6c {
  strings:
    $key_8f6c = { dc 03 [2] f8 0d [2] d3 21 [2] fd 03 [2] e9 18 [2] e6 02 [2] f8 1f [2] fa 1e [2] e1 18 [2] fd 1f [2] e1 30 }

  condition:
    any of them
}