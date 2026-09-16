rule TTP_XOR_QUAD_CurrentVersionRun_b66c {
  strings:
    $key_b66c = { e5 03 [2] c1 0d [2] ea 21 [2] c4 03 [2] d0 18 [2] df 02 [2] c1 1f [2] c3 1e [2] d8 18 [2] c4 1f [2] d8 30 }

  condition:
    any of them
}