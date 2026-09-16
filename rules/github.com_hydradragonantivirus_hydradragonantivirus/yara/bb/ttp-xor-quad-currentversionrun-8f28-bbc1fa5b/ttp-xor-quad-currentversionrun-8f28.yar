rule TTP_XOR_QUAD_CurrentVersionRun_8f28 {
  strings:
    $key_8f28 = { dc 47 [2] f8 49 [2] d3 65 [2] fd 47 [2] e9 5c [2] e6 46 [2] f8 5b [2] fa 5a [2] e1 5c [2] fd 5b [2] e1 74 }

  condition:
    any of them
}