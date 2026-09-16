rule TTP_XOR_QUAD_CurrentVersionRun_93c3 {
  strings:
    $key_93c3 = { c0 ac [2] e4 a2 [2] cf 8e [2] e1 ac [2] f5 b7 [2] fa ad [2] e4 b0 [2] e6 b1 [2] fd b7 [2] e1 b0 [2] fd 9f }

  condition:
    any of them
}