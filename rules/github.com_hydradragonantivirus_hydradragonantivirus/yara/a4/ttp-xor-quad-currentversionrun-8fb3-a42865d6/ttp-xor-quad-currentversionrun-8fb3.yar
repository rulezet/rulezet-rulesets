rule TTP_XOR_QUAD_CurrentVersionRun_8fb3 {
  strings:
    $key_8fb3 = { dc dc [2] f8 d2 [2] d3 fe [2] fd dc [2] e9 c7 [2] e6 dd [2] f8 c0 [2] fa c1 [2] e1 c7 [2] fd c0 [2] e1 ef }

  condition:
    any of them
}