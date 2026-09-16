rule TTP_XOR_QUAD_CurrentVersionRun_b6ef {
  strings:
    $key_b6ef = { e5 80 [2] c1 8e [2] ea a2 [2] c4 80 [2] d0 9b [2] df 81 [2] c1 9c [2] c3 9d [2] d8 9b [2] c4 9c [2] d8 b3 }

  condition:
    any of them
}