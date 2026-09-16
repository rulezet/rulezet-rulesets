rule TTP_XOR_QUAD_CurrentVersionRun_b3ee {
  strings:
    $key_b3ee = { e0 81 [2] c4 8f [2] ef a3 [2] c1 81 [2] d5 9a [2] da 80 [2] c4 9d [2] c6 9c [2] dd 9a [2] c1 9d [2] dd b2 }

  condition:
    any of them
}