rule TTP_XOR_QUAD_CurrentVersionRun_b7e0 {
  strings:
    $key_b7e0 = { e4 8f [2] c0 81 [2] eb ad [2] c5 8f [2] d1 94 [2] de 8e [2] c0 93 [2] c2 92 [2] d9 94 [2] c5 93 [2] d9 bc }

  condition:
    any of them
}