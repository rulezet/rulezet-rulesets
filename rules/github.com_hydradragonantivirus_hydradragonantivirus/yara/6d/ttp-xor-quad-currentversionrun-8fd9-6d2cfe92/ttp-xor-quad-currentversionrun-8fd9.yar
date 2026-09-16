rule TTP_XOR_QUAD_CurrentVersionRun_8fd9 {
  strings:
    $key_8fd9 = { dc b6 [2] f8 b8 [2] d3 94 [2] fd b6 [2] e9 ad [2] e6 b7 [2] f8 aa [2] fa ab [2] e1 ad [2] fd aa [2] e1 85 }

  condition:
    any of them
}