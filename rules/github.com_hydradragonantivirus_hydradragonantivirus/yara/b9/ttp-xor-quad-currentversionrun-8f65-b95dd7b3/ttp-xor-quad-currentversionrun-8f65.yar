rule TTP_XOR_QUAD_CurrentVersionRun_8f65 {
  strings:
    $key_8f65 = { dc 0a [2] f8 04 [2] d3 28 [2] fd 0a [2] e9 11 [2] e6 0b [2] f8 16 [2] fa 17 [2] e1 11 [2] fd 16 [2] e1 39 }

  condition:
    any of them
}