rule TTP_XOR_QUAD_CurrentVersionRun_8f18 {
  strings:
    $key_8f18 = { dc 77 [2] f8 79 [2] d3 55 [2] fd 77 [2] e9 6c [2] e6 76 [2] f8 6b [2] fa 6a [2] e1 6c [2] fd 6b [2] e1 44 }

  condition:
    any of them
}