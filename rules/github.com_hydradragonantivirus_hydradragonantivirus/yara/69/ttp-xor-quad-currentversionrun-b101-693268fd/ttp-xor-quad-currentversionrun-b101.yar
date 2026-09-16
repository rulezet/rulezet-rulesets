rule TTP_XOR_QUAD_CurrentVersionRun_b101 {
  strings:
    $key_b101 = { e2 6e [2] c6 60 [2] ed 4c [2] c3 6e [2] d7 75 [2] d8 6f [2] c6 72 [2] c4 73 [2] df 75 [2] c3 72 [2] df 5d }

  condition:
    any of them
}