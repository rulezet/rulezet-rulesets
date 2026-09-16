rule TTP_XOR_QUAD_CurrentVersionRun_93c2 {
  strings:
    $key_93c2 = { c0 ad [2] e4 a3 [2] cf 8f [2] e1 ad [2] f5 b6 [2] fa ac [2] e4 b1 [2] e6 b0 [2] fd b6 [2] e1 b1 [2] fd 9e }

  condition:
    any of them
}