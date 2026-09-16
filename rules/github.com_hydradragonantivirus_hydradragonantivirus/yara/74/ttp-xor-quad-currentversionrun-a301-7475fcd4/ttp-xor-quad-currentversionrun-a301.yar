rule TTP_XOR_QUAD_CurrentVersionRun_a301 {
  strings:
    $key_a301 = { f0 6e [2] d4 60 [2] ff 4c [2] d1 6e [2] c5 75 [2] ca 6f [2] d4 72 [2] d6 73 [2] cd 75 [2] d1 72 [2] cd 5d }

  condition:
    any of them
}