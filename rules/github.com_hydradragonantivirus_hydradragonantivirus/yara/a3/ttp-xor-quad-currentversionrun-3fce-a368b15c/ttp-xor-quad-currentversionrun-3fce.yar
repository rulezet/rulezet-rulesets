rule TTP_XOR_QUAD_CurrentVersionRun_3fce {
  strings:
    $key_3fce = { 6c a1 [2] 48 af [2] 63 83 [2] 4d a1 [2] 59 ba [2] 56 a0 [2] 48 bd [2] 4a bc [2] 51 ba [2] 4d bd [2] 51 92 }

  condition:
    any of them
}