rule TTP_XOR_QUAD_CurrentVersionRun_b76a {
  strings:
    $key_b76a = { e4 05 [2] c0 0b [2] eb 27 [2] c5 05 [2] d1 1e [2] de 04 [2] c0 19 [2] c2 18 [2] d9 1e [2] c5 19 [2] d9 36 }

  condition:
    any of them
}