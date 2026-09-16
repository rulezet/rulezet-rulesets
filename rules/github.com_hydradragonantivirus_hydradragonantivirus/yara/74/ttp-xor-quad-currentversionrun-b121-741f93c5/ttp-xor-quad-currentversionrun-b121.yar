rule TTP_XOR_QUAD_CurrentVersionRun_b121 {
  strings:
    $key_b121 = { e2 4e [2] c6 40 [2] ed 6c [2] c3 4e [2] d7 55 [2] d8 4f [2] c6 52 [2] c4 53 [2] df 55 [2] c3 52 [2] df 7d }

  condition:
    any of them
}