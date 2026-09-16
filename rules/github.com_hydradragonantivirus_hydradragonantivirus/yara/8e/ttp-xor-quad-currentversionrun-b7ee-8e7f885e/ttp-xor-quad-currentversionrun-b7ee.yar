rule TTP_XOR_QUAD_CurrentVersionRun_b7ee {
  strings:
    $key_b7ee = { e4 81 [2] c0 8f [2] eb a3 [2] c5 81 [2] d1 9a [2] de 80 [2] c0 9d [2] c2 9c [2] d9 9a [2] c5 9d [2] d9 b2 }

  condition:
    any of them
}