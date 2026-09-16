rule TTP_XOR_QUAD_CurrentVersionRun_b61e {
  strings:
    $key_b61e = { e5 71 [2] c1 7f [2] ea 53 [2] c4 71 [2] d0 6a [2] df 70 [2] c1 6d [2] c3 6c [2] d8 6a [2] c4 6d [2] d8 42 }

  condition:
    any of them
}