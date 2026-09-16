rule TTP_XOR_QUAD_CurrentVersionRun_b630 {
  strings:
    $key_b630 = { e5 5f [2] c1 51 [2] ea 7d [2] c4 5f [2] d0 44 [2] df 5e [2] c1 43 [2] c3 42 [2] d8 44 [2] c4 43 [2] d8 6c }

  condition:
    any of them
}