rule TTP_XOR_QUAD_CurrentVersionRun_8fd2 {
  strings:
    $key_8fd2 = { dc bd [2] f8 b3 [2] d3 9f [2] fd bd [2] e9 a6 [2] e6 bc [2] f8 a1 [2] fa a0 [2] e1 a6 [2] fd a1 [2] e1 8e }

  condition:
    any of them
}