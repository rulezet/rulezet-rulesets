rule TTP_XOR_QUAD_CurrentVersionRun_8fe9 {
  strings:
    $key_8fe9 = { dc 86 [2] f8 88 [2] d3 a4 [2] fd 86 [2] e9 9d [2] e6 87 [2] f8 9a [2] fa 9b [2] e1 9d [2] fd 9a [2] e1 b5 }

  condition:
    any of them
}