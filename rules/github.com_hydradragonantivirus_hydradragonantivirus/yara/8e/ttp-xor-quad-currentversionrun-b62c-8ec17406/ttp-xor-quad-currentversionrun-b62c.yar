rule TTP_XOR_QUAD_CurrentVersionRun_b62c {
  strings:
    $key_b62c = { e5 43 [2] c1 4d [2] ea 61 [2] c4 43 [2] d0 58 [2] df 42 [2] c1 5f [2] c3 5e [2] d8 58 [2] c4 5f [2] d8 70 }

  condition:
    any of them
}