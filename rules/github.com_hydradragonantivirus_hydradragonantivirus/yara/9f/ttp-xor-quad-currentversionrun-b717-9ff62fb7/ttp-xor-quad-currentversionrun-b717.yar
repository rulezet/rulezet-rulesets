rule TTP_XOR_QUAD_CurrentVersionRun_b717 {
  strings:
    $key_b717 = { e4 78 [2] c0 76 [2] eb 5a [2] c5 78 [2] d1 63 [2] de 79 [2] c0 64 [2] c2 65 [2] d9 63 [2] c5 64 [2] d9 4b }

  condition:
    any of them
}