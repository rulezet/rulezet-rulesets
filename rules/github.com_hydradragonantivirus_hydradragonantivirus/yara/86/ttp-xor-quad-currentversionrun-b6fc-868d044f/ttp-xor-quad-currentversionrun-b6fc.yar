rule TTP_XOR_QUAD_CurrentVersionRun_b6fc {
  strings:
    $key_b6fc = { e5 93 [2] c1 9d [2] ea b1 [2] c4 93 [2] d0 88 [2] df 92 [2] c1 8f [2] c3 8e [2] d8 88 [2] c4 8f [2] d8 a0 }

  condition:
    any of them
}