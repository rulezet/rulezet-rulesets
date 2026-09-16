rule TTP_XOR_QUAD_CurrentVersionRun_b13c {
  strings:
    $key_b13c = { e2 53 [2] c6 5d [2] ed 71 [2] c3 53 [2] d7 48 [2] d8 52 [2] c6 4f [2] c4 4e [2] df 48 [2] c3 4f [2] df 60 }

  condition:
    any of them
}