rule TTP_XOR_QUAD_CurrentVersionRun_8f34 {
  strings:
    $key_8f34 = { dc 5b [2] f8 55 [2] d3 79 [2] fd 5b [2] e9 40 [2] e6 5a [2] f8 47 [2] fa 46 [2] e1 40 [2] fd 47 [2] e1 68 }

  condition:
    any of them
}