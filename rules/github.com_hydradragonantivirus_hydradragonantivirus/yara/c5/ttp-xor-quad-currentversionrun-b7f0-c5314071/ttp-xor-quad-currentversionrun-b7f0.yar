rule TTP_XOR_QUAD_CurrentVersionRun_b7f0 {
  strings:
    $key_b7f0 = { e4 9f [2] c0 91 [2] eb bd [2] c5 9f [2] d1 84 [2] de 9e [2] c0 83 [2] c2 82 [2] d9 84 [2] c5 83 [2] d9 ac }

  condition:
    any of them
}