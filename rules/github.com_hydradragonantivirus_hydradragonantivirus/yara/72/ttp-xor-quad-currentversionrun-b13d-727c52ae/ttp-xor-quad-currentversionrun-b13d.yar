rule TTP_XOR_QUAD_CurrentVersionRun_b13d {
  strings:
    $key_b13d = { e2 52 [2] c6 5c [2] ed 70 [2] c3 52 [2] d7 49 [2] d8 53 [2] c6 4e [2] c4 4f [2] df 49 [2] c3 4e [2] df 61 }

  condition:
    any of them
}