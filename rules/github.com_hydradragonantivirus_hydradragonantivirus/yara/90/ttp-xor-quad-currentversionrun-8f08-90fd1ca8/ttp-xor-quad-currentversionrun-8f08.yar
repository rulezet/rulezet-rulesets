rule TTP_XOR_QUAD_CurrentVersionRun_8f08 {
  strings:
    $key_8f08 = { dc 67 [2] f8 69 [2] d3 45 [2] fd 67 [2] e9 7c [2] e6 66 [2] f8 7b [2] fa 7a [2] e1 7c [2] fd 7b [2] e1 54 }

  condition:
    any of them
}