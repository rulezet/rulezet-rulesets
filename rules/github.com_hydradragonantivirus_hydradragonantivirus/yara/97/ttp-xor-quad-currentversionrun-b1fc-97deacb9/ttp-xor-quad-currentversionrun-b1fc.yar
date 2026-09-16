rule TTP_XOR_QUAD_CurrentVersionRun_b1fc {
  strings:
    $key_b1fc = { e2 93 [2] c6 9d [2] ed b1 [2] c3 93 [2] d7 88 [2] d8 92 [2] c6 8f [2] c4 8e [2] df 88 [2] c3 8f [2] df a0 }

  condition:
    any of them
}