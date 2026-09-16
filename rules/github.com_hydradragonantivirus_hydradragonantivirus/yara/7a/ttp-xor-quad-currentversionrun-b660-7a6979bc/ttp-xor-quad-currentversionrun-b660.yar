rule TTP_XOR_QUAD_CurrentVersionRun_b660 {
  strings:
    $key_b660 = { e5 0f [2] c1 01 [2] ea 2d [2] c4 0f [2] d0 14 [2] df 0e [2] c1 13 [2] c3 12 [2] d8 14 [2] c4 13 [2] d8 3c }

  condition:
    any of them
}