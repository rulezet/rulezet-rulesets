rule TTP_XOR_QUAD_CurrentVersionRun_8fe6 {
  strings:
    $key_8fe6 = { dc 89 [2] f8 87 [2] d3 ab [2] fd 89 [2] e9 92 [2] e6 88 [2] f8 95 [2] fa 94 [2] e1 92 [2] fd 95 [2] e1 ba }

  condition:
    any of them
}