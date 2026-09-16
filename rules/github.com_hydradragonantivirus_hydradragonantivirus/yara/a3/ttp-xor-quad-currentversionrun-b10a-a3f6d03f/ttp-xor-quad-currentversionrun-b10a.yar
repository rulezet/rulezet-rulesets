rule TTP_XOR_QUAD_CurrentVersionRun_b10a {
  strings:
    $key_b10a = { e2 65 [2] c6 6b [2] ed 47 [2] c3 65 [2] d7 7e [2] d8 64 [2] c6 79 [2] c4 78 [2] df 7e [2] c3 79 [2] df 56 }

  condition:
    any of them
}