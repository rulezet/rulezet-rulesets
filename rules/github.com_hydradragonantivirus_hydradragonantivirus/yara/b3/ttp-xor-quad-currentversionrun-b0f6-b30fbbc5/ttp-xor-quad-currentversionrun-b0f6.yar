rule TTP_XOR_QUAD_CurrentVersionRun_b0f6 {
  strings:
    $key_b0f6 = { e3 99 [2] c7 97 [2] ec bb [2] c2 99 [2] d6 82 [2] d9 98 [2] c7 85 [2] c5 84 [2] de 82 [2] c2 85 [2] de aa }

  condition:
    any of them
}