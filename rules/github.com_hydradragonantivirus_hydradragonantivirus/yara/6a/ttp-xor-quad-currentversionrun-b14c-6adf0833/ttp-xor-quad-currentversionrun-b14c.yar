rule TTP_XOR_QUAD_CurrentVersionRun_b14c {
  strings:
    $key_b14c = { e2 23 [2] c6 2d [2] ed 01 [2] c3 23 [2] d7 38 [2] d8 22 [2] c6 3f [2] c4 3e [2] df 38 [2] c3 3f [2] df 10 }

  condition:
    any of them
}