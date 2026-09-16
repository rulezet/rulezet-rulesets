rule TTP_XOR_QUAD_CurrentVersionRun_93cf {
  strings:
    $key_93cf = { c0 a0 [2] e4 ae [2] cf 82 [2] e1 a0 [2] f5 bb [2] fa a1 [2] e4 bc [2] e6 bd [2] fd bb [2] e1 bc [2] fd 93 }

  condition:
    any of them
}