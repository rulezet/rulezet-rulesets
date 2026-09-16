rule TTP_XOR_QUAD_CurrentVersionRun_8fb4 {
  strings:
    $key_8fb4 = { dc db [2] f8 d5 [2] d3 f9 [2] fd db [2] e9 c0 [2] e6 da [2] f8 c7 [2] fa c6 [2] e1 c0 [2] fd c7 [2] e1 e8 }

  condition:
    any of them
}