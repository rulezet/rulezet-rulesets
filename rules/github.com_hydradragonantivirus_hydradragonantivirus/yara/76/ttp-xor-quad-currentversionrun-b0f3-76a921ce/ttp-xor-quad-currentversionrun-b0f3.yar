rule TTP_XOR_QUAD_CurrentVersionRun_b0f3 {
  strings:
    $key_b0f3 = { e3 9c [2] c7 92 [2] ec be [2] c2 9c [2] d6 87 [2] d9 9d [2] c7 80 [2] c5 81 [2] de 87 [2] c2 80 [2] de af }

  condition:
    any of them
}