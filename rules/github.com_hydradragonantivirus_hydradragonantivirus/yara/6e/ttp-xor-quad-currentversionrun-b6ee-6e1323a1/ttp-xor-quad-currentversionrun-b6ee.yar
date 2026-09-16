rule TTP_XOR_QUAD_CurrentVersionRun_b6ee {
  strings:
    $key_b6ee = { e5 81 [2] c1 8f [2] ea a3 [2] c4 81 [2] d0 9a [2] df 80 [2] c1 9d [2] c3 9c [2] d8 9a [2] c4 9d [2] d8 b2 }

  condition:
    any of them
}