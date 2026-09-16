rule TTP_XOR_QUAD_CurrentVersionRun_7fce {
  strings:
    $key_7fce = { 2c a1 [2] 08 af [2] 23 83 [2] 0d a1 [2] 19 ba [2] 16 a0 [2] 08 bd [2] 0a bc [2] 11 ba [2] 0d bd [2] 11 92 }

  condition:
    any of them
}