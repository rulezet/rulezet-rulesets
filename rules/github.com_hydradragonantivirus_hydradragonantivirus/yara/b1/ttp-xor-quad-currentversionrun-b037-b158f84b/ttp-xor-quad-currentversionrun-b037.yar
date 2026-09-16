rule TTP_XOR_QUAD_CurrentVersionRun_b037 {
  strings:
    $key_b037 = { e3 58 [2] c7 56 [2] ec 7a [2] c2 58 [2] d6 43 [2] d9 59 [2] c7 44 [2] c5 45 [2] de 43 [2] c2 44 [2] de 6b }

  condition:
    any of them
}