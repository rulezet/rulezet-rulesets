rule TTP_XOR_QUAD_CurrentVersionRun_b60e {
  strings:
    $key_b60e = { e5 61 [2] c1 6f [2] ea 43 [2] c4 61 [2] d0 7a [2] df 60 [2] c1 7d [2] c3 7c [2] d8 7a [2] c4 7d [2] d8 52 }

  condition:
    any of them
}