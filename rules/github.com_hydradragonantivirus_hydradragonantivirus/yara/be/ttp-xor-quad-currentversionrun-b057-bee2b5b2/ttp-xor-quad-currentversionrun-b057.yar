rule TTP_XOR_QUAD_CurrentVersionRun_b057 {
  strings:
    $key_b057 = { e3 38 [2] c7 36 [2] ec 1a [2] c2 38 [2] d6 23 [2] d9 39 [2] c7 24 [2] c5 25 [2] de 23 [2] c2 24 [2] de 0b }

  condition:
    any of them
}