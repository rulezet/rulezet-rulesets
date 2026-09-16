rule TTP_XOR_QUAD_CurrentVersionRun_b16c {
  strings:
    $key_b16c = { e2 03 [2] c6 0d [2] ed 21 [2] c3 03 [2] d7 18 [2] d8 02 [2] c6 1f [2] c4 1e [2] df 18 [2] c3 1f [2] df 30 }

  condition:
    any of them
}