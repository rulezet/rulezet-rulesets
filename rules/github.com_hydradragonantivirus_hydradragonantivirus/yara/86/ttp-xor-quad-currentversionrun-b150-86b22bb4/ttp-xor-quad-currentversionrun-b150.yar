rule TTP_XOR_QUAD_CurrentVersionRun_b150 {
  strings:
    $key_b150 = { e2 3f [2] c6 31 [2] ed 1d [2] c3 3f [2] d7 24 [2] d8 3e [2] c6 23 [2] c4 22 [2] df 24 [2] c3 23 [2] df 0c }

  condition:
    any of them
}