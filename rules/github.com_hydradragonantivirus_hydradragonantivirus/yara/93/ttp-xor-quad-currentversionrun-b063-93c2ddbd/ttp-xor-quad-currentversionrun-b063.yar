rule TTP_XOR_QUAD_CurrentVersionRun_b063 {
  strings:
    $key_b063 = { e3 0c [2] c7 02 [2] ec 2e [2] c2 0c [2] d6 17 [2] d9 0d [2] c7 10 [2] c5 11 [2] de 17 [2] c2 10 [2] de 3f }

  condition:
    any of them
}