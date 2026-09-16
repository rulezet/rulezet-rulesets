rule TTP_XOR_QUAD_CurrentVersionRun_b600 {
  strings:
    $key_b600 = { e5 6f [2] c1 61 [2] ea 4d [2] c4 6f [2] d0 74 [2] df 6e [2] c1 73 [2] c3 72 [2] d8 74 [2] c4 73 [2] d8 5c }

  condition:
    any of them
}