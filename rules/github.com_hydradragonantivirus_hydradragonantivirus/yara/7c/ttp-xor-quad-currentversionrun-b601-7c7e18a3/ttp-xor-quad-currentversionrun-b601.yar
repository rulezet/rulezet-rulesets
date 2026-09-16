rule TTP_XOR_QUAD_CurrentVersionRun_b601 {
  strings:
    $key_b601 = { e5 6e [2] c1 60 [2] ea 4c [2] c4 6e [2] d0 75 [2] df 6f [2] c1 72 [2] c3 73 [2] d8 75 [2] c4 72 [2] d8 5d }

  condition:
    any of them
}