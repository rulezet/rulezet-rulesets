rule TTP_XOR_QUAD_CurrentVersionRun_b7ef {
  strings:
    $key_b7ef = { e4 80 [2] c0 8e [2] eb a2 [2] c5 80 [2] d1 9b [2] de 81 [2] c0 9c [2] c2 9d [2] d9 9b [2] c5 9c [2] d9 b3 }

  condition:
    any of them
}