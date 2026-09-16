rule TTP_XOR_QUAD_CurrentVersionRun_b613 {
  strings:
    $key_b613 = { e5 7c [2] c1 72 [2] ea 5e [2] c4 7c [2] d0 67 [2] df 7d [2] c1 60 [2] c3 61 [2] d8 67 [2] c4 60 [2] d8 4f }

  condition:
    any of them
}