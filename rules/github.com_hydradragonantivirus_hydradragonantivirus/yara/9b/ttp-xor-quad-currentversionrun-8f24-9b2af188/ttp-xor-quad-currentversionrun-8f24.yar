rule TTP_XOR_QUAD_CurrentVersionRun_8f24 {
  strings:
    $key_8f24 = { dc 4b [2] f8 45 [2] d3 69 [2] fd 4b [2] e9 50 [2] e6 4a [2] f8 57 [2] fa 56 [2] e1 50 [2] fd 57 [2] e1 78 }

  condition:
    any of them
}