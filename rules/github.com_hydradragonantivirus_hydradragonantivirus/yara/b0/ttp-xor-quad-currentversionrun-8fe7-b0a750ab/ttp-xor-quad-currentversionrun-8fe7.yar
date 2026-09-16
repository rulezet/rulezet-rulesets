rule TTP_XOR_QUAD_CurrentVersionRun_8fe7 {
  strings:
    $key_8fe7 = { dc 88 [2] f8 86 [2] d3 aa [2] fd 88 [2] e9 93 [2] e6 89 [2] f8 94 [2] fa 95 [2] e1 93 [2] fd 94 [2] e1 bb }

  condition:
    any of them
}