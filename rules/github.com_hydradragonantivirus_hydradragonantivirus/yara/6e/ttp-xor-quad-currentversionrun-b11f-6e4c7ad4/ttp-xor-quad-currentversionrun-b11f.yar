rule TTP_XOR_QUAD_CurrentVersionRun_b11f {
  strings:
    $key_b11f = { e2 70 [2] c6 7e [2] ed 52 [2] c3 70 [2] d7 6b [2] d8 71 [2] c6 6c [2] c4 6d [2] df 6b [2] c3 6c [2] df 43 }

  condition:
    any of them
}