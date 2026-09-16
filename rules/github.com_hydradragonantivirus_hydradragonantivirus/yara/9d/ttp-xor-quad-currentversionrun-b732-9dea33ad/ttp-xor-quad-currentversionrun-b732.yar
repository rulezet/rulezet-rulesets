rule TTP_XOR_QUAD_CurrentVersionRun_b732 {
  strings:
    $key_b732 = { e4 5d [2] c0 53 [2] eb 7f [2] c5 5d [2] d1 46 [2] de 5c [2] c0 41 [2] c2 40 [2] d9 46 [2] c5 41 [2] d9 6e }

  condition:
    any of them
}