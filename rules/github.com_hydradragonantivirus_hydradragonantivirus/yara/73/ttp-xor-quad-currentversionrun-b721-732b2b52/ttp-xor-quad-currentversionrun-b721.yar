rule TTP_XOR_QUAD_CurrentVersionRun_b721 {
  strings:
    $key_b721 = { e4 4e [2] c0 40 [2] eb 6c [2] c5 4e [2] d1 55 [2] de 4f [2] c0 52 [2] c2 53 [2] d9 55 [2] c5 52 [2] d9 7d }

  condition:
    any of them
}