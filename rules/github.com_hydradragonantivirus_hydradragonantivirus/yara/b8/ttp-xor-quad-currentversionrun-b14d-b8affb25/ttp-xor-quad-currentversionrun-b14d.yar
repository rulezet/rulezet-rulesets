rule TTP_XOR_QUAD_CurrentVersionRun_b14d {
  strings:
    $key_b14d = { e2 22 [2] c6 2c [2] ed 00 [2] c3 22 [2] d7 39 [2] d8 23 [2] c6 3e [2] c4 3f [2] df 39 [2] c3 3e [2] df 11 }

  condition:
    any of them
}