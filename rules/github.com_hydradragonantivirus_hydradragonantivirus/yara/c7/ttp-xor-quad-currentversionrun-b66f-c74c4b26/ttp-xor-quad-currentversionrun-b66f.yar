rule TTP_XOR_QUAD_CurrentVersionRun_b66f {
  strings:
    $key_b66f = { e5 00 [2] c1 0e [2] ea 22 [2] c4 00 [2] d0 1b [2] df 01 [2] c1 1c [2] c3 1d [2] d8 1b [2] c4 1c [2] d8 33 }

  condition:
    any of them
}